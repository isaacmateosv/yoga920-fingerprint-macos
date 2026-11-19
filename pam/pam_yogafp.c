/*
 * pam_yogafp - authenticate with the yoga-fp fingerprint daemon (yogafpd).
 *
 *   /etc/pam.d/sudo_local:
 *     auth       sufficient     /usr/local/lib/pam/pam_yogafp.so
 *
 * Behaviour:
 *   - Remote sessions (PAM_RHOST set, or SSH_CONNECTION/SSH_TTY in the environment) -> PAM_IGNORE,
 *     so nobody can trigger a fingerprint prompt from SSH and have a person at the machine approve it.
 *   - Daemon missing, not root, or not enrolled -> PAM_IGNORE (falls through to the password).
 *   - The daemon socket's peer must be uid 0 (getpeereid), so a user process can't impersonate it.
 *   - Match -> PAM_SUCCESS. No match / timeout -> PAM_AUTH_ERR ("sufficient" then continues to password).
 *
 * Module options:  tries=N (1-5, default 3)   timeout=S (2-30 s per try, default 10)   debug
 */
#define PAM_SM_AUTH
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <syslog.h>
#include <errno.h>

#define SOCK_PATH "/var/run/yogafpd.sock"

static int opt_int(int argc, const char **argv, const char *name, int def, int lo, int hi) {
    size_t n = strlen(name);
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], name, n) == 0 && argv[i][n] == '=') {
            int v = atoi(argv[i] + n + 1);
            if (v >= lo && v <= hi) return v;
        }
    }
    return def;
}

static int has_opt(int argc, const char **argv, const char *name) {
    for (int i = 0; i < argc; i++) if (strcmp(argv[i], name) == 0) return 1;
    return 0;
}

static void info(pam_handle_t *pamh, const char *msg) {
    const struct pam_conv *conv = NULL;
    if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS || !conv || !conv->conv) return;
    struct pam_message m = { .msg_style = PAM_TEXT_INFO, .msg = (char *)msg };
    const struct pam_message *mp = &m;
    struct pam_response *resp = NULL;
    conv->conv(1, &mp, &resp, conv->appdata_ptr);
    if (resp) { free(resp->resp); free(resp); }
}

/* Extract a JSON string value for "key" from a flat one-line object written by yogafpd. */
static int json_str(const char *line, const char *key, char *out, size_t outlen) {
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\": \"", key);
    const char *p = strstr(line, pat);
    if (!p) return 0;
    p += strlen(pat);
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < outlen) {
        if (*p == '\\' && p[1]) p++;
        out[i++] = *p++;
    }
    out[i] = 0;
    return 1;
}

static int is_remote(pam_handle_t *pamh) {
    const char *rhost = NULL;
    if (pam_get_item(pamh, PAM_RHOST, (const void **)&rhost) == PAM_SUCCESS && rhost && *rhost) return 1;
    if (getenv("SSH_CONNECTION") || getenv("SSH_TTY") || getenv("SSH_CLIENT")) return 1;
    const char *e = pam_getenv(pamh, "SSH_CONNECTION");
    return e && *e;
}

/* Tell yogafpd (peer must be root) that uid just authenticated with a password: Touch ID-style policy
   (fingerprint requires a password within 48 h / after 5 failures). Best effort, never blocks auth. */
static void report_password(uid_t uid) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return;
    struct sockaddr_un sa; memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX; strlcpy(sa.sun_path, SOCK_PATH, sizeof sa.sun_path);
    uid_t pe; gid_t pg;
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) == 0 && getpeereid(fd, &pe, &pg) == 0 && pe == 0) {
        struct timeval tv = { 3, 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        char req[96];
        int n = snprintf(req, sizeof req, "{\"op\": \"password_ok\", \"uid\": %u}\n", (unsigned)uid);
        if (write(fd, req, (size_t)n) == n) { char buf[256]; (void)read(fd, buf, sizeof buf); }
    }
    close(fd);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags;
    int debug = has_opt(argc, argv, "debug");
    int tries = opt_int(argc, argv, "tries", 3, 1, 5);
    int tmo = opt_int(argc, argv, "timeout", 10, 2, 30);

    if (is_remote(pamh)) {
        if (debug) syslog(LOG_AUTH | LOG_DEBUG, "pam_yogafp: remote session, skipping");
        return PAM_IGNORE;
    }

    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user) return PAM_IGNORE;
    struct passwd *pw = getpwnam(user);
    if (!pw) return PAM_IGNORE;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return PAM_IGNORE;
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    strlcpy(sa.sun_path, SOCK_PATH, sizeof sa.sun_path);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        if (debug) syslog(LOG_AUTH | LOG_DEBUG, "pam_yogafp: daemon not reachable (%s)", strerror(errno));
        close(fd);
        return PAM_IGNORE;
    }

    uid_t peuid; gid_t pegid;
    if (getpeereid(fd, &peuid, &pegid) != 0 || peuid != 0) {
        syslog(LOG_AUTH | LOG_WARNING, "pam_yogafp: daemon socket not owned by root; refusing");
        close(fd);
        return PAM_IGNORE;
    }

    /* Overall read timeout: blank + tries * (timeout + lift) with margin. */
    struct timeval tv = { .tv_sec = 5 + tries * (tmo + 8), .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    /* Service name (e.g. "sudo") lets the menu bar app show who is asking. Keep it to [a-z0-9_-]. */
    const char *svc_raw = NULL;
    char svc[33] = "pam";
    if (pam_get_item(pamh, PAM_SERVICE, (const void **)&svc_raw) == PAM_SUCCESS && svc_raw) {
        size_t j = 0;
        for (size_t i = 0; svc_raw[i] && j + 1 < sizeof svc; i++) {
            char c = svc_raw[i];
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-')
                svc[j++] = c;
        }
        svc[j] = 0;
        if (!j) strlcpy(svc, "pam", sizeof svc);
    }

    char req[224];
    int n = snprintf(req, sizeof req,
                     "{\"op\": \"verify\", \"uid\": %u, \"tries\": %d, \"timeout\": %d, \"service\": \"%s\"}\n",
                     (unsigned)pw->pw_uid, tries, tmo, svc);
    if (write(fd, req, (size_t)n) != n) { close(fd); return PAM_IGNORE; }

    FILE *f = fdopen(fd, "r");
    if (!f) { close(fd); return PAM_IGNORE; }

    int result = PAM_IGNORE;
    char line[2048], msg[256];
    int prompted = 0;
    while (fgets(line, sizeof line, f)) {
        if (strstr(line, "\"done\": true")) {
            if (strstr(line, "\"ok\": true") && strstr(line, "\"match\": true")) {
                result = PAM_SUCCESS;
            } else if (strstr(line, "\"ok\": true")) {
                result = PAM_AUTH_ERR;          /* touched but not recognized / timed out */
            } else {
                /* daemon error: not enrolled, sensor unavailable, locked out ... -> password */
                if (json_str(line, "error", msg, sizeof msg) && (debug || strstr(msg, "too many") || strstr(msg, "cancelled") || strstr(msg, "password required")))
                    info(pamh, msg);
                result = PAM_IGNORE;
            }
            break;
        }
        if (strstr(line, "\"event\": \"place\"")) {
            if (!prompted) { info(pamh, "Touch the fingerprint sensor (or wait to use your password)"); prompted = 1; }
        } else if (strstr(line, "\"event\": \"nomatch\"") || strstr(line, "\"event\": \"partial\"")) {
            if (json_str(line, "msg", msg, sizeof msg)) info(pamh, msg);
        }
    }
    fclose(f);

    if (result == PAM_SUCCESS) pam_set_data(pamh, "yogafp_fingerprint", (void *)1, NULL);
    syslog(LOG_AUTH | LOG_NOTICE, "pam_yogafp: user %s: %s", user,
           result == PAM_SUCCESS ? "fingerprint accepted" : result == PAM_AUTH_ERR ? "fingerprint rejected" : "skipped");
    return result;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)argc; (void)argv;
    if (flags & (PAM_ESTABLISH_CRED | PAM_REINITIALIZE_CRED)) {
        const void *fp = NULL;
        if (pam_get_data(pamh, "yogafp_fingerprint", &fp) != PAM_SUCCESS || !fp) {
            const char *user = NULL;
            struct passwd *pw;
            if (pam_get_user(pamh, &user, NULL) == PAM_SUCCESS && user && (pw = getpwnam(user)))
                report_password(pw->pw_uid);
        }
    }
    return PAM_SUCCESS;
}
