#define _POSIX_C_SOURCE 200809L

#include "commands.h"

#include "../keypair.h"
#include "../secure_mem.h"
#include "../tower.h"
#include "../util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

// Search PATH for the validator admin CLI. agave-validator (current) takes
// precedence over solana-validator (legacy alias).
static int find_validator_bin(char *out, size_t out_size)
{
    static const char *cands[] = { "agave-validator", "solana-validator" };
    const char *PATH = getenv("PATH");
    if (!PATH) return -1;

    for (size_t k = 0; k < sizeof(cands)/sizeof(cands[0]); k++) {
        const char *bin = cands[k];
        const char *p = PATH;
        while (*p) {
            const char *colon = strchr(p, ':');
            size_t n = colon ? (size_t)(colon - p) : strlen(p);
            if (n > 0 && n < 1024) {
                char path[1100];
                snprintf(path, sizeof(path), "%.*s/%s", (int)n, p, bin);
                if (access(path, X_OK) == 0) {
                    snprintf(out, out_size, "%s", path);
                    return 0;
                }
            }
            if (!colon) break;
            p = colon + 1;
        }
    }
    return -1;
}

static int run(const char *argv[], const char *bin)
{
    pid_t pid = fork();
    if (pid < 0) {
        log_error("fork: %s", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        execv(bin, (char *const *)argv);
        fprintf(stderr, "exec %s: %s\n", bin, strerror(errno));
        _exit(127);
    }
    int wstatus = 0;
    if (waitpid(pid, &wstatus, 0) < 0) {
        log_error("waitpid: %s", strerror(errno));
        return -1;
    }
    if (WIFEXITED(wstatus)) return WEXITSTATUS(wstatus);
    return -1;
}

int cmd_swap(const cmd_opts_t *o)
{
    // The argv[0] decides the direction: "swap-out" or "swap-in".
    if (o->positional_count < 1) {
        log_error("swap subcommand required (swap-out | swap-in)");
        return VIDX_ERR_USAGE;
    }
    const char *direction = o->positional[0];
    bool is_out = strcmp(direction, "swap-out") == 0 || strcmp(direction, "out") == 0;
    bool is_in  = strcmp(direction, "swap-in")  == 0 || strcmp(direction, "in")  == 0;
    if (!is_out && !is_in) {
        log_error("unknown swap direction: %s", direction);
        return VIDX_ERR_USAGE;
    }

    if (!o->ledger_dir) {
        log_error("--ledger DIR required");
        return VIDX_ERR_USAGE;
    }
    if (!o->keypair_path) {
        log_error("--keypair PATH required");
        return VIDX_ERR_USAGE;
    }

    // Sanity-check the keypair we're about to install.
    uint8_t *sk = (uint8_t *)secure_alloc(64);
    if (!sk) return VIDX_ERR_INTERNAL;
    secure_register(sk, 64);

    char b58[64];
    vidx_status_t s = keypair_read(o->keypair_path, sk, NULL, b58,
                                   o->allow_loose_perms);
    secure_free(sk);
    if (s != VIDX_OK) return s;
    log_ok("keypair %s parses as identity %s", o->keypair_path, b58);

    char bin[1100];
    bool found = find_validator_bin(bin, sizeof(bin)) == 0;

    // Build the command we'd run.
    const char *args_out[16] = {0};
    int ai = 0;

    if (found) args_out[ai++] = bin;
    else       args_out[ai++] = "agave-validator";

    args_out[ai++] = "-l";
    args_out[ai++] = o->ledger_dir;
    args_out[ai++] = "set-identity";
    if (is_in) args_out[ai++] = "--require-tower";
    args_out[ai++] = o->keypair_path;
    args_out[ai++] = NULL;

    fprintf(stderr, "\nWould run:\n  ");
    for (int i = 0; args_out[i]; i++) fprintf(stderr, "%s ", args_out[i]);
    fprintf(stderr, "\n\n");

    if (o->dry_run) {
        log_ok("--dry-run: not invoking the validator binary.");
        log_info("Run the command above on the validator host when ready.");
        return VIDX_OK;
    }

    if (!found) {
        log_warn("agave-validator / solana-validator not found in PATH. "
                 "Run the command above manually on the host (or pass --dry-run "
                 "to suppress this warning).");
        return VIDX_OK;
    }

    if (is_in && !o->skip_preflight) {
        // Make sure the tower is in the ledger dir if we're going to require it.
        char tower_path[4096];
        bool present = false;
        if (tower_locate(o->ledger_dir, b58, tower_path, sizeof(tower_path), &present) != VIDX_OK
            || !present) {
            log_error("--require-tower will fail: tower file %s is not present. "
                      "Place it there first (the bundle from `vid-transfer receive` "
                      "writes it for you with --ledger), or pass --skip-preflight.",
                      tower_path);
            return VIDX_ERR_VERIFY;
        }
        log_ok("tower file present: %s", tower_path);
    }

    if (!o->force_overwrite) {
        char q[256];
        snprintf(q, sizeof(q),
                 "About to %s identity to %s on %s. Continue?",
                 is_in ? "INSTALL" : "ROTATE OUT", b58, o->ledger_dir);
        if (!prompt_yes_no(q, false)) {
            log_warn("aborted by user");
            return VIDX_ERR_USER_ABORT;
        }
    }

    int rc = run(args_out, bin);
    if (rc != 0) {
        log_error("validator returned exit code %d", rc);
        return VIDX_ERR_INTERNAL;
    }
    log_ok("identity %s on %s", is_in ? "set" : "rotated out", o->ledger_dir);
    return 0;
}
