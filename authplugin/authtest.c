/* authtest (installed as "YogaFP Self-Check") - request one authorization right, the way an app asking for admin
 * rights does; the dialog shows the program name, hence the friendly install name.
 * Used by the installer to prove the plugin works on a private test right before any system right is changed.
 *   usage: authtest <right-name>            exit 0 = granted
 *          authtest --no-ui <right-name>    no dialog allowed: granted only if macOS needs no authentication
 *                                           (root callers, credentials already held)
 *          authtest --reuse <right-name>    request twice on the same authorization, the second time with no
 *                                           dialog allowed; prints "granted reused" when the first approval counts */
#include <Security/Authorization.h>
#include <stdio.h>
#include <string.h>

static OSStatus copy_right(AuthorizationRef ref, const char *right, int interactive) {
    AuthorizationItem item = { right, 0, NULL, 0 };
    AuthorizationRights rights = { 1, &item };
    AuthorizationFlags f = kAuthorizationFlagExtendRights | (interactive ? kAuthorizationFlagInteractionAllowed : 0);
    return AuthorizationCopyRights(ref, &rights, kAuthorizationEmptyEnvironment, f, NULL);
}

static int report(OSStatus st, const char *suffix) {
    switch (st) {
    case errAuthorizationSuccess:            printf("granted%s\n", suffix); return 0;
    case errAuthorizationCanceled:           printf("cancelled\n"); return 1;
    case errAuthorizationDenied:             printf("denied\n"); return 1;
    case errAuthorizationInteractionNotAllowed: printf("needs-dialog\n"); return 1;
    default:                                 printf("error %d\n", (int)st); return 4;
    }
}

int main(int argc, char **argv) {
    int noui = 0, reuse = 0;
    if (argc == 3 && strcmp(argv[1], "--no-ui") == 0) noui = 1;
    else if (argc == 3 && strcmp(argv[1], "--reuse") == 0) reuse = 1;
    else if (argc != 2) { fprintf(stderr, "usage: %s [--no-ui|--reuse] <right>\n", argv[0]); return 2; }
    const char *right = argv[argc - 1];
    AuthorizationRef ref;
    if (AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &ref) != errAuthorizationSuccess)
        return 3;
    OSStatus st = copy_right(ref, right, !noui);
    int rc;
    if (reuse && st == errAuthorizationSuccess) {
        OSStatus again = copy_right(ref, right, 0);
        rc = report(again, " reused");
        if (again != errAuthorizationSuccess) { printf("(first request was granted)\n"); rc = 5; }
    } else {
        rc = report(st, "");
    }
    AuthorizationFree(ref, kAuthorizationFlagDestroyRights);
    return rc;
}
