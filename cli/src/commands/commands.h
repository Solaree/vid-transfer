#ifndef VIDX_COMMANDS_H
#define VIDX_COMMANDS_H

#include "../util.h"

typedef struct {
    const char *relay_url;
    const char *rpc_url;
    const char *keypair_path;     // for `send`, `status`
    const char *out_path;         // for `receive`
    const char *ledger_dir;       // for `send` (locate tower)
    const char *tower_path;       // explicit tower override
    const char *expected_pubkey;  // optional pin for `receive`
    const char *cluster;          // mainnet|testnet|devnet
    bool        no_tower;         // skip tower
    bool        skip_preflight;   // bypass status checks (NOT recommended)
    bool        allow_loose_perms;
    bool        force_overwrite;  // for `receive` if out_path exists
    int         wait_seconds;     // long-poll timeout
    bool        json_output;      // machine-readable mode
    int         tls_strict;
    bool        dry_run;          // print the command instead of running it
    const char *code;             // for `send`
    const char *positional[8];
    int         positional_count;
} cmd_opts_t;

void cmd_opts_init(cmd_opts_t *o);

int cmd_init   (const cmd_opts_t *o);
int cmd_doctor (const cmd_opts_t *o);
int cmd_status (const cmd_opts_t *o);
int cmd_receive(const cmd_opts_t *o);
int cmd_send   (const cmd_opts_t *o);
int cmd_swap   (const cmd_opts_t *o);

#endif
