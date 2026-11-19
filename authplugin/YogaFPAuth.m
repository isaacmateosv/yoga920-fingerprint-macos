// YogaFPAuth - macOS authorization plugin: fingerprint (yoga-fp) for admin dialogs, password always available.
//
// Mechanisms (used together, in this order, by an "evaluate-mechanisms" right):
//   YogaFP:fingerprint,privileged   runs as root, no UI. Finds the console user, requires admin group membership,
//                                   asks yogafpd (/var/run/yogafpd.sock, peer must be root) to verify a touch.
//                                   NEVER grants on its own: it only records "yogafp-verified" in the context and
//                                   always lets evaluation continue (result Allow = "continue").
//   YogaFP:password                 runs in SecurityAgent (UI). If the fingerprint was verified for an admin, it
//                                   allows immediately. Otherwise it shows a password dialog, verifies the password
//                                   with OpenDirectory and checks admin membership.
// Fail-safe: any error in the fingerprint step falls through to the password dialog.
#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <OpenDirectory/OpenDirectory.h>
#import <SystemConfiguration/SystemConfiguration.h>
#include <Security/AuthorizationPlugin.h>
#include <Security/AuthorizationTags.h>
#include <membership.h>
#include <pwd.h>
#include <grp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <os/log.h>
#include <unistd.h>

#define SOCK_PATH "/var/run/yogafpd.sock"
#define CTX_VERIFIED "yogafp-verified"
#define CTX_USER "yogafp-user"

typedef struct {
    const AuthorizationCallbacks *cb;
} Plugin;

typedef struct {
    Plugin *plugin;
    AuthorizationEngineRef engine;
    int kind;                       // 0 = fingerprint, 1 = password
    volatile int deactivated;
} Mech;

static os_log_t yfp_log(void) {
    static os_log_t l; static dispatch_once_t once;
    dispatch_once(&once, ^{ l = os_log_create("com.yogafp.authplugin", "auth"); });
    return l;
}

// Visible with: log show --predicate 'subsystem == "com.yogafp.authplugin"'   (no secrets are logged)
static void logmsg(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    os_log(yfp_log(), "%{public}s", s.UTF8String);
}

// ------------------------------------------------------------------ helpers
static BOOL user_is_admin(uid_t uid) {
    uuid_t uu, gu; int member = 0;
    struct group *g = getgrnam("admin");
    if (!g) return NO;
    if (mbr_uid_to_uuid(uid, uu) != 0 || mbr_gid_to_uuid(g->gr_gid, gu) != 0) return NO;
    if (mbr_check_membership(uu, gu, &member) != 0) return NO;
    return member != 0;
}

static NSString *hint_string(Mech *m, const char *key) {
    const AuthorizationValue *v = NULL;
    if (m->plugin->cb->GetHintValue(m->engine, key, &v) != errAuthorizationSuccess || !v || !v->data) return nil;
    NSString *s = [[NSString alloc] initWithBytes:v->data length:v->length encoding:NSUTF8StringEncoding];
    return [s stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"\0"]];
}

static NSString *ctx_string(Mech *m, const char *key) {
    const AuthorizationValue *v = NULL; AuthorizationContextFlags f = 0;
    if (m->plugin->cb->GetContextValue(m->engine, key, &f, &v) != errAuthorizationSuccess || !v || !v->data) return nil;
    NSString *s = [[NSString alloc] initWithBytes:v->data length:v->length encoding:NSUTF8StringEncoding];
    return [s stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"\0"]];
}

static void ctx_set_string(Mech *m, const char *key, NSString *val, AuthorizationContextFlags flags) {
    const char *c = val.UTF8String;
    AuthorizationValue v = { strlen(c) + 1, (void *)c };
    m->plugin->cb->SetContextValue(m->engine, key, flags, &v);
}

// Tell authd who was authenticated (what builtin:authenticate would set).
static void set_identity(Mech *m, NSString *user, uid_t uid, gid_t gid) {
    ctx_set_string(m, kAuthorizationEnvironmentUsername, user, kAuthorizationContextFlagExtractable);
    AuthorizationValue vu = { sizeof(uid), &uid };
    m->plugin->cb->SetContextValue(m->engine, "uid", kAuthorizationContextFlagExtractable, &vu);
    AuthorizationValue vg = { sizeof(gid), &gid };
    m->plugin->cb->SetContextValue(m->engine, "gid", kAuthorizationContextFlagExtractable, &vg);
}

static NSString *requesting_app(Mech *m) {
    NSString *p = hint_string(m, "client-path");
    if (!p.length) return @"An application";
    NSString *name = p.lastPathComponent;
    for (NSString *c in [p pathComponents]) if ([c hasSuffix:@".app"]) { name = c.stringByDeletingPathExtension; break; }
    return name.length ? name : @"An application";
}

// ------------------------------------------------------------------ fingerprint (privileged, root)
static BOOL fingerprint_verify(uid_t uid, NSString *service) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NO;
    struct sockaddr_un sa; memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX; strlcpy(sa.sun_path, SOCK_PATH, sizeof sa.sun_path);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) { close(fd); return NO; }
    uid_t peuid; gid_t pegid;
    if (getpeereid(fd, &peuid, &pegid) != 0 || peuid != 0) { logmsg(@"daemon socket not owned by root"); close(fd); return NO; }
    struct timeval tv = { 45, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    NSString *req = [NSString stringWithFormat:@"{\"op\": \"verify\", \"uid\": %u, \"tries\": 3, \"timeout\": 10, \"service\": \"%@\"}\n",
                     (unsigned)uid, service];
    const char *r = req.UTF8String;
    if (write(fd, r, strlen(r)) != (ssize_t)strlen(r)) { close(fd); return NO; }
    FILE *f = fdopen(fd, "r");
    if (!f) { close(fd); return NO; }
    BOOL ok = NO; char line[2048];
    while (fgets(line, sizeof line, f)) {
        if (strstr(line, "\"done\": true")) {
            ok = strstr(line, "\"ok\": true") && strstr(line, "\"match\": true");
            break;
        }
    }
    fclose(f);
    return ok;
}

static void invoke_fingerprint(Mech *m) {
    // The engine and callbacks stay valid until MechanismDestroy; the work runs off the engine's thread.
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        ctx_set_string(m, CTX_VERIFIED, @"0", 0);
        uid_t cuid = 0; gid_t cgid = 0;
        CFStringRef cu = SCDynamicStoreCopyConsoleUser(NULL, &cuid, &cgid);
        NSString *user = cu ? (__bridge_transfer NSString *)cu : nil;
        if (user.length && ![user isEqualToString:@"loginwindow"] && cuid != 0 && user_is_admin(cuid)) {
            if (fingerprint_verify(cuid, @"admin")) {
                ctx_set_string(m, CTX_VERIFIED, @"1", 0);
                ctx_set_string(m, CTX_USER, user, 0);
                set_identity(m, user, cuid, cgid);
                logmsg(@"fingerprint verified for %@ (%@)", user, requesting_app(m));
            } else {
                logmsg(@"fingerprint not verified for %@; falling back to password", user);
            }
        }
        if (!m->deactivated) m->plugin->cb->SetResult(m->engine, kAuthorizationResultAllow);   // continue to password mech
    });
}

// ------------------------------------------------------------------ password dialog (SecurityAgent, UI)
static BOOL password_ok(NSString *user, NSString *pw, uid_t *uid_out, gid_t *gid_out) {
    struct passwd *p = getpwnam(user.UTF8String);
    if (!p) return NO;
    NSError *e = nil;
    ODNode *node = [ODNode nodeWithSession:[ODSession defaultSession] type:kODNodeTypeAuthentication error:&e];
    ODRecord *rec = [node recordWithRecordType:kODRecordTypeUsers name:user attributes:nil error:&e];
    if (!rec || ![rec verifyPassword:pw error:&e]) return NO;
    if (!user_is_admin(p->pw_uid)) return NO;
    *uid_out = p->pw_uid; *gid_out = p->pw_gid;
    return YES;
}

static void invoke_password(Mech *m) {
    NSString *verified = ctx_string(m, CTX_VERIFIED);
    NSString *vuser = ctx_string(m, CTX_USER);
    if ([verified isEqualToString:@"1"] && vuser.length) {
        struct passwd *p = getpwnam(vuser.UTF8String);
        if (p && user_is_admin(p->pw_uid)) {
            logmsg(@"allowing: fingerprint verified for %@", vuser);
            set_identity(m, vuser, p->pw_uid, p->pw_gid);
            m->plugin->cb->SetResult(m->engine, kAuthorizationResultAllow);
            return;
        }
    }
    NSString *app = requesting_app(m);
    uid_t cuid = 0; gid_t cgid = 0;
    CFStringRef cu = SCDynamicStoreCopyConsoleUser(NULL, &cuid, &cgid);
    NSString *suggested = cu ? (__bridge_transfer NSString *)cu : @"";
    if ([suggested isEqualToString:@"loginwindow"]) suggested = @"";

    dispatch_async(dispatch_get_main_queue(), ^{
        int attempts = 0;
        while (!m->deactivated) {
            NSAlert *a = [NSAlert new];
            a.messageText = [NSString stringWithFormat:@"%@ wants to make changes.", app];
            a.informativeText = attempts ? @"Incorrect user name or password. Try again."
                                         : @"Enter an administrator's name and password to allow this.";
            a.icon = [NSImage imageWithSystemSymbolName:@"lock.fill" accessibilityDescription:nil];
            NSView *box = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, 260, 56)];
            NSTextField *u = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 30, 260, 24)];
            u.placeholderString = @"User Name"; u.stringValue = suggested;
            NSSecureTextField *pw = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, 0, 260, 24)];
            pw.placeholderString = @"Password";
            [box addSubview:u]; [box addSubview:pw];
            a.accessoryView = box;
            [a addButtonWithTitle:@"OK"]; [a addButtonWithTitle:@"Cancel"];
            a.window.level = NSModalPanelWindowLevel + 1;
            a.window.initialFirstResponder = suggested.length ? pw : u;
            [NSApp activateIgnoringOtherApps:YES];
            NSModalResponse resp = [a runModal];
            if (m->deactivated) break;
            if (resp != NSAlertFirstButtonReturn) {
                m->plugin->cb->SetResult(m->engine, kAuthorizationResultUserCanceled);
                return;
            }
            uid_t uid; gid_t gid;
            NSString *user = [u.stringValue stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
            if (user.length && password_ok(user, pw.stringValue, &uid, &gid)) {
                logmsg(@"password accepted for %@", user);
                set_identity(m, user, uid, gid);
                m->plugin->cb->SetResult(m->engine, kAuthorizationResultAllow);
                return;
            }
            if (++attempts >= 3) {
                m->plugin->cb->SetResult(m->engine, kAuthorizationResultDeny);
                return;
            }
        }
    });
}

// ------------------------------------------------------------------ plugin interface
static OSStatus PluginDestroy(AuthorizationPluginRef inPlugin) { free(inPlugin); return errAuthorizationSuccess; }

static OSStatus MechanismCreate(AuthorizationPluginRef inPlugin, AuthorizationEngineRef inEngine,
                                AuthorizationMechanismId mechanismId, AuthorizationMechanismRef *outMechanism) {
    Mech *m = calloc(1, sizeof(Mech));
    if (!m) return errAuthorizationInternal;
    m->plugin = (Plugin *)inPlugin; m->engine = inEngine;
    if (strcmp(mechanismId, "fingerprint") == 0) m->kind = 0;
    else if (strcmp(mechanismId, "password") == 0) m->kind = 1;
    else { free(m); return errAuthorizationInternal; }
    *outMechanism = m;
    return errAuthorizationSuccess;
}

static OSStatus MechanismInvoke(AuthorizationMechanismRef inMechanism) {
    Mech *m = (Mech *)inMechanism;
    @autoreleasepool {
        logmsg(@"invoked %s mechanism (uid %d)", m->kind == 0 ? "fingerprint" : "password", (int)getuid());
        if (m->kind == 0) invoke_fingerprint(m); else invoke_password(m);
    }
    return errAuthorizationSuccess;
}

static OSStatus MechanismDeactivate(AuthorizationMechanismRef inMechanism) {
    Mech *m = (Mech *)inMechanism;
    m->deactivated = 1;
    if (m->kind == 1) dispatch_async(dispatch_get_main_queue(), ^{ [NSApp abortModal]; });
    return m->plugin->cb->DidDeactivate(m->engine);
}

static OSStatus MechanismDestroy(AuthorizationMechanismRef inMechanism) {
    // Give any in-flight async block time to observe deactivation before freeing.
    Mech *m = (Mech *)inMechanism;
    m->deactivated = 1;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 60 * NSEC_PER_SEC), dispatch_get_global_queue(0, 0), ^{ free(m); });
    return errAuthorizationSuccess;
}

static AuthorizationPluginInterface gInterface = {
    kAuthorizationPluginInterfaceVersion, PluginDestroy, MechanismCreate, MechanismInvoke, MechanismDeactivate, MechanismDestroy
};

extern OSStatus AuthorizationPluginCreate(const AuthorizationCallbacks *callbacks, AuthorizationPluginRef *outPlugin,
                                          const AuthorizationPluginInterface **outPluginInterface)
    __attribute__((visibility("default")));

OSStatus AuthorizationPluginCreate(const AuthorizationCallbacks *callbacks, AuthorizationPluginRef *outPlugin,
                                   const AuthorizationPluginInterface **outPluginInterface) {
    Plugin *p = calloc(1, sizeof(Plugin));
    if (!p) return errAuthorizationInternal;
    p->cb = callbacks;
    logmsg(@"plugin loaded (uid %d)", (int)getuid());
    *outPlugin = p;
    *outPluginInterface = &gInterface;
    return errAuthorizationSuccess;
}
