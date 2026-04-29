#define _POSIX_C_SOURCE 200809L

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include "commands/commands.h"
#include "relay.h"
#include "secure_mem.h"
#include "solana_rpc.h"
#include "util.h"

static void print_version(void)
{
    fprintf(stderr, "vid-transfer %s\n", VIDX_VERSION);
}

static void print_usage(FILE *f)
{
    fprintf(f,
"vid-transfer — secure Solana validator identity migration\n"
"\n"
"USAGE\n"
"  vid-transfer <command> [options]\n"
"\n"
"COMMANDS\n"
"  init            write a default config to ~/.vid-transfer/config.toml\n"
"  doctor          run diagnostics (libsodium, relay, RPC, optional keypair)\n"
"  status          inspect a validator-keypair.json (vote account, leader window)\n"
"\n"
"  receive         generate a pairing code and wait for an inbound identity\n"
"  send <CODE>     send a local validator-keypair.json to a paired receiver\n"
"\n"
"  swap-out        switch the local validator to an unstaked identity\n"
"                  (calls `agave-validator -l <ledger> set-identity <unstaked>`)\n"
"  swap-in         install a real identity (calls `set-identity --require-tower`)\n"
"\n"
"COMMON OPTIONS\n"
"  --keypair PATH       path to validator-keypair.json (send/status/swap)\n"
"  --out PATH           output path for received keypair (receive)\n"
"  --ledger DIR         ledger directory (locate/place tower-1_9-<id>.bin)\n"
"  --tower PATH         explicit tower file path (overrides --ledger lookup)\n"
"  --no-tower           do NOT include the tower in the bundle (DANGEROUS)\n"
"  --expected-pubkey K  pin the received identity (receive)\n"
"  --relay URL          relay URL (default: " VIDX_DEFAULT_RELAY ", or $VIDX_RELAY)\n"
"  --rpc URL            Solana JSON-RPC URL (default: mainnet-beta)\n"
"  --cluster N          mainnet | testnet | devnet (sets default --rpc)\n"
"  --wait SECONDS       receive long-poll timeout (default: 600)\n"
"  --force              overwrite existing files (receive) / no confirm (swap)\n"
"  --skip-preflight     skip leader-schedule / tower checks (DANGEROUS)\n"
"  --allow-loose-perms  read keypairs whose mode is wider than 0600\n"
"  --insecure-tls       disable TLS cert verification (DANGEROUS — testing only)\n"
"  --json               machine-readable output where supported\n"
"  --dry-run            for swap-out / swap-in: print the validator command\n"
"                       instead of executing it (useful for demos & rehearsals)\n"
"  -v, --verbose        more logging  (-vv = debug)\n"
"  -q, --quiet          only errors\n"
"  -V, --version        print version and exit\n"
"  -h, --help           print this help and exit\n"
"\n"
"EXAMPLES\n"
"  # On the new host:\n"
"  $ vid-transfer receive --out new-validator-keypair.json --ledger /mnt/ledger \\\n"
"      --expected-pubkey 7Np4...JxZ\n"
"\n"
"  # On the old host:\n"
"  $ vid-transfer send <PAIRING-CODE> \\\n"
"      --keypair /etc/solana/validator-keypair.json --ledger /mnt/ledger\n"
"\n"
"  # Hot-swap on each side:\n"
"  $ vid-transfer swap-out --ledger /mnt/ledger --keypair /etc/solana/unstaked.json\n"
"  $ vid-transfer swap-in  --ledger /mnt/ledger --keypair new-validator-keypair.json\n"
"\n"
);
}

static int set_cluster(cmd_opts_t *o, const char *name)
{
    if (strcasecmp(name, "mainnet") == 0 || strcasecmp(name, "mainnet-beta") == 0) {
        o->cluster = "mainnet";
        o->rpc_url = VIDX_DEFAULT_RPC_MAINNET;
    } else if (strcasecmp(name, "testnet") == 0) {
        o->cluster = "testnet";
        o->rpc_url = VIDX_DEFAULT_RPC_TESTNET;
    } else if (strcasecmp(name, "devnet") == 0) {
        o->cluster = "devnet";
        o->rpc_url = VIDX_DEFAULT_RPC_DEVNET;
    } else {
        return -1;
    }
    return 0;
}

enum {
    OPT_KEYPAIR = 1000,
    OPT_OUT,
    OPT_LEDGER,
    OPT_TOWER,
    OPT_NO_TOWER,
    OPT_EXPECTED,
    OPT_RELAY,
    OPT_RPC,
    OPT_CLUSTER,
    OPT_WAIT,
    OPT_FORCE,
    OPT_SKIP_PREFLIGHT,
    OPT_LOOSE,
    OPT_INSECURE_TLS,
    OPT_JSON,
    OPT_DRY_RUN,
};

int main(int argc, char **argv)
{
    if (argc < 2) {
        print_usage(stderr);
        return 1;
    }

    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(stdout);
        return 0;
    }
    if (strcmp(argv[1], "-V") == 0 || strcmp(argv[1], "--version") == 0) {
        print_version();
        return 0;
    }

    if (secure_init() != 0) return 1;

    cmd_opts_t o;
    cmd_opts_init(&o);

    // Pick up env defaults.
    const char *env_relay = getenv("VIDX_RELAY");
    if (env_relay && env_relay[0]) o.relay_url = env_relay;
    const char *env_rpc   = getenv("VIDX_RPC");
    if (env_rpc && env_rpc[0]) o.rpc_url = env_rpc;

    const char *cmd = argv[1];

    // For send, the next arg is the pairing code; consume it before getopt
    // to keep the parser simple.
    int arg_offset = 2;
    if (strcmp(cmd, "send") == 0 && argc >= 3 && argv[2][0] != '-') {
        o.code = argv[2];
        arg_offset = 3;
    }

    // For swap-out / swap-in, record the direction as positional[0].
    if (strcmp(cmd, "swap-out") == 0 || strcmp(cmd, "swap-in") == 0
        || strcmp(cmd, "swap") == 0) {
        o.positional[o.positional_count++] = cmd;
    }

    static const struct option longopts[] = {
        {"keypair",          required_argument, 0, OPT_KEYPAIR},
        {"out",              required_argument, 0, OPT_OUT},
        {"ledger",           required_argument, 0, OPT_LEDGER},
        {"tower",            required_argument, 0, OPT_TOWER},
        {"no-tower",         no_argument,       0, OPT_NO_TOWER},
        {"expected-pubkey",  required_argument, 0, OPT_EXPECTED},
        {"relay",            required_argument, 0, OPT_RELAY},
        {"rpc",              required_argument, 0, OPT_RPC},
        {"cluster",          required_argument, 0, OPT_CLUSTER},
        {"wait",             required_argument, 0, OPT_WAIT},
        {"force",            no_argument,       0, OPT_FORCE},
        {"skip-preflight",   no_argument,       0, OPT_SKIP_PREFLIGHT},
        {"allow-loose-perms",no_argument,       0, OPT_LOOSE},
        {"insecure-tls",     no_argument,       0, OPT_INSECURE_TLS},
        {"json",             no_argument,       0, OPT_JSON},
        {"dry-run",          no_argument,       0, OPT_DRY_RUN},
        {"verbose",          no_argument,       0, 'v'},
        {"quiet",            no_argument,       0, 'q'},
        {"version",          no_argument,       0, 'V'},
        {"help",             no_argument,       0, 'h'},
        {0, 0, 0, 0},
    };

    // Re-base argv for getopt.
    int new_argc = argc - arg_offset + 1;
    char **new_argv = (char **)calloc((size_t)new_argc + 1, sizeof(char *));
    if (!new_argv) return 1;
    new_argv[0] = (char *)cmd;
    for (int i = 0; i < new_argc - 1; i++) new_argv[i + 1] = argv[arg_offset + i];

    optind = 1;
    int c;
    int verbose = 0;
    while ((c = getopt_long(new_argc, new_argv, "vqVh", longopts, NULL)) != -1) {
        switch (c) {
            case OPT_KEYPAIR:        o.keypair_path = optarg; break;
            case OPT_OUT:            o.out_path = optarg; break;
            case OPT_LEDGER:         o.ledger_dir = optarg; break;
            case OPT_TOWER:          o.tower_path = optarg; break;
            case OPT_NO_TOWER:       o.no_tower = true; break;
            case OPT_EXPECTED:       o.expected_pubkey = optarg; break;
            case OPT_RELAY:          o.relay_url = optarg; break;
            case OPT_RPC:            o.rpc_url = optarg; break;
            case OPT_CLUSTER:
                if (set_cluster(&o, optarg) != 0) {
                    log_error("unknown --cluster: %s", optarg);
                    free(new_argv);
                    return 2;
                }
                break;
            case OPT_WAIT: {
                char *end = NULL;
                long v = strtol(optarg, &end, 10);
                if (!end || end == optarg || v < 5 || v > 86400) {
                    log_error("--wait must be 5..86400 seconds");
                    free(new_argv); return 2;
                }
                o.wait_seconds = (int)v;
                break;
            }
            case OPT_FORCE:          o.force_overwrite = true; break;
            case OPT_SKIP_PREFLIGHT: o.skip_preflight = true; break;
            case OPT_LOOSE:          o.allow_loose_perms = true; break;
            case OPT_INSECURE_TLS:   o.tls_strict = 0; break;
            case OPT_JSON:           o.json_output = true; break;
            case OPT_DRY_RUN:        o.dry_run = true; break;
            case 'v':                verbose++; break;
            case 'q':                log_set_level(LOG_QUIET); break;
            case 'V':                print_version(); free(new_argv); return 0;
            case 'h':                print_usage(stdout); free(new_argv); return 0;
            case '?':
            default:
                free(new_argv);
                return 2;
        }
    }
    if (verbose >= 2) log_set_level(LOG_DEBUG);
    else if (verbose == 1) log_set_level(LOG_VERBOSE);

    // Pick up extra positional args (for `swap` we already pushed direction).
    for (int i = optind; i < new_argc; i++) {
        if (o.positional_count < (int)(sizeof(o.positional)/sizeof(o.positional[0]))) {
            o.positional[o.positional_count++] = new_argv[i];
        }
    }
    free(new_argv);

    if (relay_init() != VIDX_OK) return 3;
    relay_set_tls_strict(o.tls_strict);

    int rc = 0;
    if      (strcmp(cmd, "init")    == 0) rc = cmd_init(&o);
    else if (strcmp(cmd, "doctor")  == 0) rc = cmd_doctor(&o);
    else if (strcmp(cmd, "status")  == 0) rc = cmd_status(&o);
    else if (strcmp(cmd, "receive") == 0) rc = cmd_receive(&o);
    else if (strcmp(cmd, "send")    == 0) rc = cmd_send(&o);
    else if (strcmp(cmd, "swap-out") == 0
          || strcmp(cmd, "swap-in")  == 0
          || strcmp(cmd, "swap")     == 0) rc = cmd_swap(&o);
    else {
        log_error("unknown command: %s", cmd);
        print_usage(stderr);
        rc = 2;
    }

    relay_cleanup();
    return rc;
}
