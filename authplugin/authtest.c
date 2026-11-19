/* authtest (installed as "YogaFP Self-Check") - request one authorization right, the way an app asking for admin
 * rights does; the dialog shows the program name, hence the friendly install name.
 * Used by the installer to prove the plugin works on a private test right before any system right is changed.
 *   usage: authtest <right-name>          exit 0 = granted */
#include <Security/Authorization.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s <right>\n", argv[0]); return 2; }
    AuthorizationRef ref;
    if (AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &ref) != errAuthorizationSuccess)
        return 3;
    AuthorizationItem item = { argv[1], 0, NULL, 0 };
    AuthorizationRights rights = { 1, &item };
    OSStatus st = AuthorizationCopyRights(ref, &rights, kAuthorizationEmptyEnvironment,
                                          kAuthorizationFlagInteractionAllowed | kAuthorizationFlagExtendRights, NULL);
    AuthorizationFree(ref, kAuthorizationFlagDestroyRights);
    switch (st) {
    case errAuthorizationSuccess:  printf("granted\n"); return 0;
    case errAuthorizationCanceled: printf("cancelled\n"); return 1;
    case errAuthorizationDenied:   printf("denied\n"); return 1;
    default:                       printf("error %d\n", (int)st); return 4;
    }
}
