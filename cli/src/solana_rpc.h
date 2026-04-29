#ifndef VIDX_SOLANA_RPC_H
#define VIDX_SOLANA_RPC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "util.h"

#define VIDX_DEFAULT_RPC_MAINNET "https://api.mainnet-beta.solana.com"
#define VIDX_DEFAULT_RPC_TESTNET "https://api.testnet.solana.com"
#define VIDX_DEFAULT_RPC_DEVNET  "https://api.devnet.solana.com"

typedef struct {
    uint64_t epoch;
    uint64_t slot_index;
    uint64_t slots_in_epoch;
    uint64_t absolute_slot;
} solana_epoch_info_t;

typedef struct {
    bool     present;
    bool     is_current;
    uint64_t activated_stake;
    uint64_t commission;
    uint64_t last_vote;
    uint64_t root_slot;
    char     vote_pubkey[64];
    char     node_pubkey[64];
} solana_vote_account_t;

typedef struct {
    uint64_t total_leader_slots;
    uint64_t next_leader_slot;     // 0 = none in this epoch
    uint64_t slots_until_next;     // distance from current slot
    bool     has_next;
} solana_leader_summary_t;

vidx_status_t solana_get_epoch_info(const char *rpc_url, solana_epoch_info_t *out);

// Look up the validator's vote account using its identity pubkey (base58).
vidx_status_t solana_get_vote_account_by_identity(const char *rpc_url,
                                                  const char *identity_b58,
                                                  solana_vote_account_t *out);

// Summarize the leader schedule for `identity_b58`. We only fetch the current
// epoch's schedule; that's enough to warn about an imminent slot.
vidx_status_t solana_get_leader_summary(const char *rpc_url,
                                        const char *identity_b58,
                                        solana_leader_summary_t *out);

// Fetch arbitrary cluster version (used in `doctor`).
vidx_status_t solana_get_version(const char *rpc_url, char *out_version, size_t out_size);

#endif
