// YogaFPAuth - macOS authorization plugin: one dialog offering fingerprint (yoga-fp) or password for admin rights.
//
// Right definition (class evaluate-mechanisms), in this order:
//   YogaFPAuth:ui               SecurityAgent (runs as the logged-in user, has UI). One window with a password field
//                               and a live fingerprint status line. As soon as it appears it asks yogafpd to verify the
//                               user's own finger, tagged with a random one-time nonce. The user may type a password or
//                               touch the sensor. It decides NOTHING: it only passes method + username + (nonce or
//                               password) to the next step through the authorization context.
//   YogaFPAuth:grant,privileged authorizationhost (root, no UI). The actual decision:
//                               fingerprint -> asks yogafpd (root-owned socket) to consume the nonce: valid only if the
//                                              daemon itself recorded a real match for that user within 60 s, once.
//                               password    -> OpenDirectory password check.
//                               Both require membership in the admin group.
// Nothing in the user session can fake a fingerprint approval: it would need a match recorded by the root daemon.
// Logs (no secrets): root step -> /var/log/yogafp-auth.log ; dialog step -> ~/Library/Logs/yogafp-auth.log
#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <OpenDirectory/OpenDirectory.h>
#include <Security/AuthorizationPlugin.h>
#include <Security/AuthorizationTags.h>
#include <Security/SecRandom.h>
#include <membership.h>
#include <pwd.h>
#include <grp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define SOCK_PATH   "/var/run/yogafpd.sock"
#define CTX_METHOD  "yogafp-method"     // "fingerprint" | "password"
#define CTX_NONCE   "yogafp-nonce"
#define CTX_PASS    "yogafp-password"   // not extractable; cleared after use
#define CTX_FAILED  "yogafp-failed"     // set by grant on a failed attempt, read by ui on retry

typedef struct { const AuthorizationCallbacks *cb; } Plugin;

typedef struct {
    Plugin *plugin;
    AuthorizationEngineRef engine;
    int kind;                       // 0 = ui, 1 = grant
    volatile int deactivated;
    void *dialog;                   // retained YFPDialog (ui)
} Mech;

// ------------------------------------------------------------------ logging (no secrets)
static void logline(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void logline(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *path = getuid() == 0 ? @"/var/log/yogafp-auth.log"
                                   : [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Logs/yogafp-auth.log"];
    NSDateFormatter *df = [NSDateFormatter new]; df.dateFormat = @"yyyy-MM-dd HH:mm:ss";
    NSString *line = [NSString stringWithFormat:@"%@ [%d] %@\n", [df stringFromDate:[NSDate date]], (int)getpid(), s];
    FILE *f = fopen(path.fileSystemRepresentation, "a");
    if (f) { fputs(line.UTF8String, f); fclose(f); chmod(path.fileSystemRepresentation, 0600); }
}

// ------------------------------------------------------------------ context helpers
static NSString *ctx_string(Mech *m, const char *key) {
    const AuthorizationValue *v = NULL; AuthorizationContextFlags fl = 0;
    if (m->plugin->cb->GetContextValue(m->engine, key, &fl, &v) != errAuthorizationSuccess || !v || !v->data || !v->length) return nil;
    NSString *s = [[NSString alloc] initWithBytes:v->data length:v->length encoding:NSUTF8StringEncoding];
    return [s stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"\0"]];
}

static void ctx_set(Mech *m, const char *key, NSString *val, AuthorizationContextFlags flags) {
    const char *c = (val ?: @"").UTF8String;
    AuthorizationValue v = { strlen(c) + 1, (void *)c };
    m->plugin->cb->SetContextValue(m->engine, key, flags, &v);
}

static NSString *hint_string(Mech *m, const char *key) {
    const AuthorizationValue *v = NULL;
    if (m->plugin->cb->GetHintValue(m->engine, key, &v) != errAuthorizationSuccess || !v || !v->data) return nil;
    NSString *s = [[NSString alloc] initWithBytes:v->data length:v->length encoding:NSUTF8StringEncoding];
    return [s stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"\0"]];
}

static NSString *requesting_app(Mech *m) {
    NSString *p = hint_string(m, "client-path");
    if (!p.length) return @"An application";
    for (NSString *c in p.pathComponents) if ([c hasSuffix:@".app"]) return c.stringByDeletingPathExtension;
    return p.lastPathComponent.length ? p.lastPathComponent : @"An application";
}

static BOOL user_is_admin(uid_t uid) {
    uuid_t uu, gu; int member = 0;
    struct group *g = getgrnam("admin");
    if (!g || mbr_uid_to_uuid(uid, uu) || mbr_gid_to_uuid(g->gr_gid, gu) || mbr_check_membership(uu, gu, &member)) return NO;
    return member != 0;
}

// ------------------------------------------------------------------ daemon socket
static int daemon_connect(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un sa; memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX; strlcpy(sa.sun_path, SOCK_PATH, sizeof sa.sun_path);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) { close(fd); return -1; }
    uid_t pe; gid_t pg;
    if (getpeereid(fd, &pe, &pg) != 0 || pe != 0) { logline(@"daemon socket not owned by root; refusing"); close(fd); return -1; }
    return fd;
}

static BOOL send_json(int fd, NSDictionary *req) {
    NSMutableData *d = [[NSJSONSerialization dataWithJSONObject:req options:0 error:nil] mutableCopy];
    [d appendBytes:"\n" length:1];
    return write(fd, d.bytes, d.length) == (ssize_t)d.length;
}

static NSDictionary *daemon_call_once(NSDictionary *req, int timeout_s) {   // one request -> final message
    int fd = daemon_connect();
    if (fd < 0) return nil;
    struct timeval tv = { timeout_s, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    if (!send_json(fd, req)) { close(fd); return nil; }
    FILE *f = fdopen(fd, "r"); if (!f) { close(fd); return nil; }
    NSDictionary *res = nil; char line[4096];
    while (fgets(line, sizeof line, f)) {
        NSDictionary *o = [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:line length:strlen(line)] options:0 error:nil];
        if ([o[@"done"] boolValue]) { res = o; break; }
    }
    fclose(f);
    return res;
}

// Attempts per authorization evaluation, kept in the SecurityAgent process: authd re-runs the ui mechanism for
// each try with the same engine, but does not hand the grant step's "failed" marker back to it.
static NSMutableDictionary<NSString *, NSArray *> *gAttempts;     // engine -> @[count, last time]
static int next_attempt(AuthorizationEngineRef engine) {
    static dispatch_once_t once; dispatch_once(&once, ^{ gAttempts = [NSMutableDictionary dictionary]; });
    NSString *k = [NSString stringWithFormat:@"%p", (void *)engine];
    NSArray *prev = gAttempts[k];
    NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
    // an engine address can be reused by a later, unrelated request: only count attempts within 2 minutes
    int n = (prev && now - [prev[1] doubleValue] < 120) ? [prev[0] intValue] + 1 : 1;
    gAttempts[k] = @[@(n), @(now)];
    if (gAttempts.count > 64) [gAttempts removeAllObjects];
    return n;
}

// ------------------------------------------------------------------ the dialog (SecurityAgent, runs as the user)
@interface YFPDialog : NSObject <NSWindowDelegate>
@property (assign) Mech *mech;
@property (strong) NSWindow *window;
@property (strong) NSTextField *userField, *status;
@property (strong) NSSecureTextField *passField;
@property (strong) NSImageView *icon;
@property (copy) NSString *nonce, *selfUser;
@property (assign) int fpfd;
@property (assign) BOOL finished;
@end

@implementation YFPDialog

- (void)stopFingerprint {
    int fd = self.fpfd;
    if (fd > 0) { self.fpfd = -1; shutdown(fd, SHUT_RDWR); }   // the daemon cancels the verify on disconnect
}

- (void)finish:(AuthorizationResult)r {
    if (self.finished) return;
    self.finished = YES;
    [self stopFingerprint];
    [self.window orderOut:nil];
    if (!self.mech->deactivated) self.mech->plugin->cb->SetResult(self.mech->engine, r);
}

- (void)setStatus:(NSString *)s ok:(BOOL)ok {
    self.status.stringValue = s ?: @"";
    if (ok) {
        self.icon.image = [NSImage imageWithSystemSymbolName:@"checkmark.circle.fill" accessibilityDescription:@"Recognized"];
        self.icon.contentTintColor = NSColor.systemGreenColor;
    }
}

- (void)okPressed:(id)sender {
    NSString *u = [self.userField.stringValue stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
    if (!u.length || !self.passField.stringValue.length) { NSBeep(); return; }
    ctx_set(self.mech, CTX_METHOD, @"password", 0);
    ctx_set(self.mech, kAuthorizationEnvironmentUsername, u, kAuthorizationContextFlagExtractable);
    ctx_set(self.mech, CTX_PASS, self.passField.stringValue, 0);
    logline(@"dialog: password submitted for %@", u);
    [self finish:kAuthorizationResultAllow];          // "continue": the root grant step decides
}

- (void)cancelPressed:(id)sender { logline(@"dialog: cancelled"); [self finish:kAuthorizationResultUserCanceled]; }
- (BOOL)windowShouldClose:(NSWindow *)w { (void)w; [self cancelPressed:nil]; return NO; }

- (void)startFingerprint {
    struct passwd *p = getpwuid(getuid());
    if (!p || !user_is_admin(getuid())) { [self setStatus:@"Enter an administrator's name and password." ok:NO]; return; }
    NSDictionary *st = daemon_call_once(@{@"op": @"status"}, 3);
    if (![st[@"enrolled"] boolValue] || ![st[@"sensor_ready"] boolValue]) {
        logline(@"dialog: fingerprint unavailable (enrolled=%@ ready=%@)", st[@"enrolled"], st[@"sensor_ready"]);
        [self setStatus:@"Fingerprint not available - enter your password." ok:NO]; return;
    }
    uint8_t rnd[16];
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof rnd, rnd) != errSecSuccess) { [self setStatus:@"" ok:NO]; return; }
    NSMutableString *n = [NSMutableString string];
    for (int i = 0; i < 16; i++) [n appendFormat:@"%02x", rnd[i]];
    self.nonce = n;
    int fd = daemon_connect();
    if (fd < 0) { [self setStatus:@"Fingerprint not available - enter your password." ok:NO]; return; }
    self.fpfd = fd;
    [self setStatus:@"Touch the fingerprint sensor" ok:NO];
    logline(@"dialog: fingerprint started for %s", p->pw_name);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        send_json(fd, @{@"op": @"verify", @"tries": @5, @"timeout": @20, @"nonce": n});
        int rfd = dup(fd);
        FILE *f = rfd >= 0 ? fdopen(rfd, "r") : NULL;
        char line[4096]; NSDictionary *done = nil;
        while (f && fgets(line, sizeof line, f)) {
            NSDictionary *o = [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:line length:strlen(line)] options:0 error:nil];
            if (!o) continue;
            if ([o[@"done"] boolValue]) { done = o; break; }
            NSString *ev = o[@"event"], *msg = o[@"msg"];
            NSString *show = [ev isEqualToString:@"place"] ? @"Touch the fingerprint sensor"
                           : ([ev isEqualToString:@"nomatch"] || [ev isEqualToString:@"partial"] || [ev isEqualToString:@"lift"]) ? msg : nil;
            if (show) dispatch_async(dispatch_get_main_queue(), ^{ if (!self.finished) [self setStatus:show ok:NO]; });
        }
        if (f) fclose(f);
        close(fd);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (self.finished) return;
            if ([done[@"ok"] boolValue] && [done[@"match"] boolValue]) {
                logline(@"dialog: fingerprint matched; handing the nonce to the root step");
                [self setStatus:@"Recognized" ok:YES];
                ctx_set(self.mech, CTX_METHOD, @"fingerprint", 0);
                ctx_set(self.mech, CTX_NONCE, self.nonce, 0);
                ctx_set(self.mech, kAuthorizationEnvironmentUsername, self.selfUser, kAuthorizationContextFlagExtractable);
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 300 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
                    [self finish:kAuthorizationResultAllow];
                });
            } else {
                NSString *why = done[@"reason"] ?: done[@"error"] ?: @"no reply";
                logline(@"dialog: fingerprint ended without a match (%@)", why);
                [self setStatus:@"Fingerprint not recognized - enter your password." ok:NO];
            }
        });
    });
}

- (void)showFor:(Mech *)m {
    self.mech = m; self.fpfd = -1;
    struct passwd *p = getpwuid(getuid());
    self.selfUser = p ? @(p->pw_name) : @"";
    BOOL retry = [ctx_string(m, CTX_FAILED) isEqualToString:@"1"] || next_attempt(m->engine) > 1;

    NSWindow *w = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 420, 250)
                                              styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable
                                                backing:NSBackingStoreBuffered defer:NO];
    w.title = @""; w.delegate = self; w.level = NSModalPanelWindowLevel + 1; w.releasedWhenClosed = NO;
    w.collectionBehavior = NSWindowCollectionBehaviorCanJoinAllSpaces | NSWindowCollectionBehaviorFullScreenAuxiliary;
    NSView *v = w.contentView;

    self.icon = [NSImageView imageViewWithImage:[NSImage imageWithSystemSymbolName:@"touchid" accessibilityDescription:@"Fingerprint"]];
    self.icon.frame = NSMakeRect(20, 178, 52, 52);
    self.icon.symbolConfiguration = [NSImageSymbolConfiguration configurationWithPointSize:40 weight:NSFontWeightRegular];
    self.icon.contentTintColor = NSColor.controlAccentColor;
    [v addSubview:self.icon];

    NSTextField *title = [NSTextField wrappingLabelWithString:[NSString stringWithFormat:@"%@ wants to make changes.", requesting_app(m)]];
    title.font = [NSFont boldSystemFontOfSize:13]; title.frame = NSMakeRect(86, 206, 314, 22); [v addSubview:title];
    NSTextField *info = [NSTextField wrappingLabelWithString:@"Touch the fingerprint sensor or enter an administrator's password to allow this."];
    info.font = [NSFont systemFontOfSize:11]; info.frame = NSMakeRect(86, 172, 314, 32); [v addSubview:info];

    self.userField = [[NSTextField alloc] initWithFrame:NSMakeRect(86, 130, 314, 24)];
    self.userField.placeholderString = @"User Name"; self.userField.stringValue = self.selfUser; [v addSubview:self.userField];
    self.passField = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(86, 98, 314, 24)];
    self.passField.placeholderString = @"Password"; self.passField.target = self; self.passField.action = @selector(okPressed:);
    [v addSubview:self.passField];

    self.status = [NSTextField labelWithString:@""];
    self.status.font = [NSFont systemFontOfSize:11]; self.status.textColor = NSColor.secondaryLabelColor;
    self.status.frame = NSMakeRect(86, 66, 314, 20); [v addSubview:self.status];

    NSButton *ok = [NSButton buttonWithTitle:@"OK" target:self action:@selector(okPressed:)];
    ok.keyEquivalent = @"\r"; ok.frame = NSMakeRect(310, 16, 90, 32); [v addSubview:ok];
    NSButton *cancel = [NSButton buttonWithTitle:@"Cancel" target:self action:@selector(cancelPressed:)];
    cancel.keyEquivalent = @"\033"; cancel.frame = NSMakeRect(214, 16, 90, 32); [v addSubview:cancel];

    [w center];
    w.initialFirstResponder = self.passField;
    self.window = w;
    [NSApp activateIgnoringOtherApps:YES];
    [w makeKeyAndOrderFront:nil];
    logline(@"dialog: shown for %@ (retry=%d)", requesting_app(m), retry);
    [self startFingerprint];
    if (retry) [self setStatus:@"Incorrect password. Try again, or touch the sensor." ok:NO];
}
@end

// ------------------------------------------------------------------ grant step (root, authorizationhost)
static BOOL od_password_ok(NSString *user, NSString *pw) {
    NSError *e = nil;
    ODNode *node = [ODNode nodeWithSession:[ODSession defaultSession] type:kODNodeTypeAuthentication error:&e];
    ODRecord *rec = [node recordWithRecordType:kODRecordTypeUsers name:user attributes:nil error:&e];
    return rec && [rec verifyPassword:pw error:&e];
}

static void set_identity(Mech *m, NSString *user, struct passwd *p) {
    uid_t uid = p->pw_uid; gid_t gid = p->pw_gid;
    ctx_set(m, kAuthorizationEnvironmentUsername, user, kAuthorizationContextFlagExtractable);
    AuthorizationValue vu = { sizeof(uid), &uid }; m->plugin->cb->SetContextValue(m->engine, "uid", kAuthorizationContextFlagExtractable, &vu);
    AuthorizationValue vg = { sizeof(gid), &gid }; m->plugin->cb->SetContextValue(m->engine, "gid", kAuthorizationContextFlagExtractable, &vg);
}

static void invoke_grant(Mech *m) {
    NSString *method = ctx_string(m, CTX_METHOD);
    NSString *user = ctx_string(m, kAuthorizationEnvironmentUsername);
    struct passwd *p = user.length ? getpwnam(user.UTF8String) : NULL;
    BOOL ok = NO;
    if (p && user_is_admin(p->pw_uid)) {
        if ([method isEqualToString:@"fingerprint"]) {
            NSString *nonce = ctx_string(m, CTX_NONCE);
            NSDictionary *r = nonce.length ? daemon_call_once(@{@"op": @"consume_match", @"nonce": nonce, @"uid": @(p->pw_uid)}, 5) : nil;
            ok = [r[@"ok"] boolValue] && [r[@"valid"] boolValue];
            logline(@"grant: fingerprint for %@ -> %@", user, ok ? @"accepted (daemon confirmed the match)" : @"rejected");
        } else if ([method isEqualToString:@"password"]) {
            NSString *pw = ctx_string(m, CTX_PASS);
            ok = pw.length && od_password_ok(user, pw);
            logline(@"grant: password for %@ -> %@", user, ok ? @"accepted" : @"rejected");
        } else {
            logline(@"grant: no method in context -> rejected");
        }
    } else {
        logline(@"grant: %@ is not an administrator (method %@) -> rejected", user ?: @"(none)", method ?: @"(none)");
    }
    ctx_set(m, CTX_PASS, @"", 0);                     // never keep the password in the context
    ctx_set(m, CTX_NONCE, @"", 0);
    ctx_set(m, CTX_FAILED, ok ? @"0" : @"1", 0);
    if (ok) set_identity(m, user, p);
    m->plugin->cb->SetResult(m->engine, ok ? kAuthorizationResultAllow : kAuthorizationResultDeny);
}

// ------------------------------------------------------------------ plugin interface
static OSStatus PluginDestroy(AuthorizationPluginRef inPlugin) { free(inPlugin); return errAuthorizationSuccess; }

static OSStatus MechanismCreate(AuthorizationPluginRef inPlugin, AuthorizationEngineRef inEngine,
                                AuthorizationMechanismId mechanismId, AuthorizationMechanismRef *outMechanism) {
    Mech *m = calloc(1, sizeof(Mech));
    if (!m) return errAuthorizationInternal;
    m->plugin = (Plugin *)inPlugin; m->engine = inEngine;
    if (strcmp(mechanismId, "ui") == 0) m->kind = 0;
    else if (strcmp(mechanismId, "grant") == 0) m->kind = 1;
    else { logline(@"unknown mechanism %s", mechanismId); free(m); return errAuthorizationInternal; }
    *outMechanism = m;
    return errAuthorizationSuccess;
}

static OSStatus MechanismInvoke(AuthorizationMechanismRef inMechanism) {
    Mech *m = (Mech *)inMechanism;
    @autoreleasepool {
        if (m->kind == 1) { invoke_grant(m); return errAuthorizationSuccess; }
        dispatch_async(dispatch_get_main_queue(), ^{
            YFPDialog *dlg = [YFPDialog new];
            m->dialog = (__bridge_retained void *)dlg;
            [dlg showFor:m];
        });
    }
    return errAuthorizationSuccess;
}

static OSStatus MechanismDeactivate(AuthorizationMechanismRef inMechanism) {
    Mech *m = (Mech *)inMechanism;
    m->deactivated = 1;
    void *dp = m->dialog;
    if (dp) dispatch_async(dispatch_get_main_queue(), ^{
        YFPDialog *dlg = (__bridge YFPDialog *)dp;
        dlg.finished = YES; [dlg stopFingerprint]; [dlg.window orderOut:nil];
    });
    return m->plugin->cb->DidDeactivate(m->engine);
}

static OSStatus MechanismDestroy(AuthorizationMechanismRef inMechanism) {
    Mech *m = (Mech *)inMechanism;
    m->deactivated = 1;
    void *dp = m->dialog; m->dialog = NULL;
    dispatch_async(dispatch_get_main_queue(), ^{     // free on the main queue, after any pending UI blocks
        if (dp) {
            YFPDialog *dlg = (__bridge_transfer YFPDialog *)dp;
            dlg.finished = YES; [dlg stopFingerprint]; [dlg.window orderOut:nil];
        }
        free(m);
    });
    return errAuthorizationSuccess;
}

static AuthorizationPluginInterface gInterface = {
    kAuthorizationPluginInterfaceVersion, PluginDestroy, MechanismCreate, MechanismInvoke, MechanismDeactivate, MechanismDestroy
};

extern OSStatus AuthorizationPluginCreate(const AuthorizationCallbacks *, AuthorizationPluginRef *,
                                          const AuthorizationPluginInterface **) __attribute__((visibility("default")));

OSStatus AuthorizationPluginCreate(const AuthorizationCallbacks *callbacks, AuthorizationPluginRef *outPlugin,
                                   const AuthorizationPluginInterface **outPluginInterface) {
    Plugin *p = calloc(1, sizeof(Plugin));
    if (!p) return errAuthorizationInternal;
    p->cb = callbacks;
    logline(@"plugin loaded");
    *outPlugin = p;
    *outPluginInterface = &gInterface;
    return errAuthorizationSuccess;
}
