#include "commands.h"

#include "../keypair.h"
#include "../relay.h"
#include "../secure_mem.h"
#include "../solana_rpc.h"
#include "../tower.h"
#include "../util.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define SAFE_SLOTS_BEFORE_LEADER 200

int cmd_status(const cmd_opts_t *o)
{
    if (!o->keypair_path) {
        log_error("--keypair PATH required");
        return VIDX_ERR_USAGE;
    }

    log_step("loading keypair %s", o->keypair_path);

    uint8_t *sk = (uint8_t *)secure_alloc(64);
    if (!sk) return VIDX_ERR_INTERNAL;
    secure_register(sk, 64);

    char identity_b58[64] = {0};
    vidx_status_t s = keypair_read(o->keypair_path, sk, NULL, identity_b58,
                                   o->allow_loose_perms);
    if (s != VIDX_OK) { secure_free(sk); return s; }
    log_ok("identity pubkey: %s", identity_b58);
    // Wipe sk now — status doesn't need the secret further.
    secure_free(sk);
    sk = NULL;

    // Tower file presence.
    if (o->ledger_dir) {
        char tower_path[4096];
        bool present = false;
        if (tower_locate(o->ledger_dir, identity_b58,
                         tower_path, sizeof(tower_path), &present) == VIDX_OK) {
            if (present) {
                struct stat st;
                if (stat(tower_path, &st) == 0) {
                    log_ok("tower:    %s (%lld bytes)", tower_path, (long long)st.st_size);
                } else {
                    log_ok("tower:    %s", tower_path);
                }
            } else {
                log_warn("tower not found at %s", tower_path);
            }
        }
    } else if (o->tower_path) {
        struct stat st;
        if (stat(o->tower_path, &st) == 0 && S_ISREG(st.st_mode)) {
            log_ok("tower:    %s (%lld bytes)", o->tower_path, (long long)st.st_size);
        } else {
            log_warn("tower:    %s — not found", o->tower_path);
        }
    }

    // Solana RPC pre-flight.
    log_step("querying Solana cluster (%s)", o->rpc_url);

    solana_epoch_info_t ei;
    s = solana_get_epoch_info(o->rpc_url, &ei);
    if (s != VIDX_OK) {
        log_warn("getEpochInfo failed (%s); skipping vote/leader checks. "
                 "If this validator is on a private cluster, set --rpc.",
                 vidx_status_str(s));
        return VIDX_OK;
    }
    log_ok("epoch %llu, slot %llu (%llu/%llu in epoch)",
           (unsigned long long)ei.epoch,
           (unsigned long long)ei.absolute_slot,
           (unsigned long long)ei.slot_index,
           (unsigned long long)ei.slots_in_epoch);

    solana_vote_account_t va;
    s = solana_get_vote_account_by_identity(o->rpc_url, identity_b58, &va);
    if (s == VIDX_OK && va.present) {
        log_ok("vote acct: %s%s",
               va.vote_pubkey,
               va.is_current ? " (active)" : " (delinquent)");
        log_ok("activated stake: %llu lamports, last vote slot %llu, root %llu",
               (unsigned long long)va.activated_stake,
               (unsigned long long)va.last_vote,
               (unsigned long long)va.root_slot);
    } else if (s == VIDX_OK) {
        log_warn("no vote account found for this identity on the chosen cluster.");
    }

    solana_leader_summary_t ls;
    s = solana_get_leader_summary(o->rpc_url, identity_b58, &ls);
    if (s == VIDX_OK) {
        if (ls.has_next) {
            log_info("next leader slot: %llu (in %llu slots, ~%llu seconds)",
                     (unsigned long long)ls.next_leader_slot,
                     (unsigned long long)ls.slots_until_next,
                     (unsigned long long)(ls.slots_until_next * 4 / 10));  // ~0.4s/slot
            if (ls.slots_until_next < SAFE_SLOTS_BEFORE_LEADER) {
                log_warn("** UNSAFE WINDOW ** — leader slot is < %d slots away. "
                         "Wait until after this leader window before swapping identity, "
                         "or you risk producing blocks on two machines.",
                         SAFE_SLOTS_BEFORE_LEADER);
                return VIDX_ERR_VERIFY;
            }
        } else {
            log_ok("no leader slots remaining in this epoch — safe window for transfer.");
        }
    }

    log_ok("status check complete");
    return 0;
}
