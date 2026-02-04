#ifndef MINING_H_
#define MINING_H_

#include "stratum_api.h"
#include <stddef.h>

typedef struct
{
    uint32_t version;
    uint32_t version_mask;
    uint8_t prev_block_hash[32];
    uint8_t merkle_root[32];
    uint32_t ntime;
    uint32_t target; // aka difficulty, aka nbits
    uint32_t starting_nonce;

    uint8_t num_midstates;
    uint8_t midstate[32];
    uint8_t midstate1[32];
    uint8_t midstate2[32];
    uint8_t midstate3[32];
    uint32_t pool_diff;
    char *jobid;
    char *extranonce2;
} bm_job;

void free_bm_job(bm_job *job);

void calculate_coinbase_tx_hash(const char *coinbase_1, const char *coinbase_2,
                                const char *extranonce, const char *extranonce_2, uint8_t dest[32]);
void calculate_coinbase_tx_hash_prebin(const uint8_t *coinbase_1_bin, size_t coinbase_1_bin_len,
                                       const uint8_t *coinbase_2_bin, size_t coinbase_2_bin_len,
                                       const char *extranonce, const char *extranonce_2, uint8_t dest[32]);
void calculate_coinbase_tx_hash_prebin_ex2_bin(const uint8_t *coinbase_1_bin, size_t coinbase_1_bin_len,
                                               const uint8_t *coinbase_2_bin, size_t coinbase_2_bin_len,
                                               const char *extranonce, const uint8_t *extranonce_2_bin,
                                               size_t extranonce_2_bin_len, uint8_t dest[32]);

void calculate_merkle_root_hash(const uint8_t coinbase_tx_hash[32], const uint8_t merkle_branches[][32], const int num_merkle_branches, uint8_t dest[32]);

void construct_bm_job(mining_notify *params, const uint8_t merkle_root[32], const uint32_t version_mask, const uint32_t difficulty, bool include_midstate, bm_job* new_job);

double test_nonce_value(const bm_job *job, const uint32_t nonce, const uint32_t rolled_version);

void extranonce_2_generate(uint64_t extranonce_2, uint32_t length, char dest[static length * 2 + 1]);
void extranonce_2_generate_bytes_and_hex(uint64_t extranonce_2, uint32_t length,
                                         uint8_t dest_bin[static length],
                                         char dest_hex[static length * 2 + 1]);

uint32_t increment_bitmask(const uint32_t value, const uint32_t mask);

#endif /* MINING_H_ */
