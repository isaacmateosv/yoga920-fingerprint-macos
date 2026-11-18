/* pamcheck - run pam_authenticate for a PAM service. Used by the installer to prove the module loads
 * and the stack still works BEFORE sudo is pointed at it.   usage: pamcheck <service> <user> */
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int conv(int n, const struct pam_message **msg, struct pam_response **resp, void *ap) {
    (void)ap;
    struct pam_response *r = calloc((size_t)n, sizeof *r);
    for (int i = 0; i < n; i++) {
        if (msg[i]->msg_style == PAM_TEXT_INFO || msg[i]->msg_style == PAM_ERROR_MSG)
            fprintf(stderr, "  [pam] %s\n", msg[i]->msg);
        else
            r[i].resp = strdup("");          /* no password: this only checks the fingerprint path */
    }
    *resp = r;
    return PAM_SUCCESS;
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s <service> <user>\n", argv[0]); return 2; }
    struct pam_conv c = { conv, NULL };
    pam_handle_t *h = NULL;
    int rc = pam_start(argv[1], argv[2], &c, &h);
    if (rc != PAM_SUCCESS) { fprintf(stderr, "pam_start: %s\n", pam_strerror(h, rc)); return 3; }
    rc = pam_authenticate(h, 0);
    printf("pam_authenticate: %s (%d)\n", pam_strerror(h, rc), rc);
    pam_end(h, rc);
    return rc == PAM_SUCCESS ? 0 : 1;
}
