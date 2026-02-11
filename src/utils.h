#ifndef UTILS_H
#define UTILS_H

#include <cmath>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <cstdint>
#include <vector>
#include <string>
#include <algorithm>

using namespace std;

namespace utils {

    // Returns the next power of 2 for a given number
    inline size_t next_power_of_two(size_t n) {
        return pow(2, ceil(log2(n)));
    }

    // Generates a random number between 0 and max_value
    inline uint32_t generate_random_number(uint32_t max_value) {
        return rand() % (max_value + 1);
    }

    // Hash function for cuckoo hashing
    inline size_t hash_mod(size_t id, size_t nonce, size_t data, size_t total_buckets) {
        std::hash<std::string> hasher;
        return hasher(std::to_string(id) + std::to_string(nonce) + std::to_string(data)) % total_buckets;
    }

    // Get candidate buckets for a given data using multiple hash functions
    inline std::vector<size_t> get_candidate_buckets(size_t data, size_t num_candidates, size_t total_buckets) {
        std::vector<size_t> candidate_buckets;
         
        for (int i = 0; i < num_candidates; i++){
            size_t nonce = 0;
            auto bucket = hash_mod(i, nonce, data, total_buckets);
            while (std::find(candidate_buckets.begin(), candidate_buckets.end(), bucket) != candidate_buckets.end()){
                nonce += 1;
                bucket = hash_mod(i, nonce, data, total_buckets);
            }
            candidate_buckets.push_back(bucket);
        }

        return candidate_buckets;
    }

    // Prints an error message and exits the program with an error code
    inline void error_exit(const std::string& error_message, int error_code = 1) {
        std::cerr << "Error: " << error_message << std::endl;
        exit(error_code);
    }

    // Prints a message to the console
    inline void print_message(const std::string& message) {
        std::cout << message << std::endl;
    }
    
// -------- deterministic 64-bit hash (SplitMix64) --------
inline uint64_t splitmix64(uint64_t x) {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

// k independent bucket hashes: bucket = h_i(key) % B
inline size_t bucket_hash(size_t key, uint64_t seed, size_t B) {
    return static_cast<size_t>(splitmix64(static_cast<uint64_t>(key) ^ seed) % static_cast<uint64_t>(B));
}

inline std::vector<size_t> get_candidate_buckets(size_t key, size_t k, size_t B, const std::vector<uint64_t>& seeds) {
    if (seeds.size() < k) throw std::invalid_argument("seeds.size() < k");
    std::vector<size_t> cands;
    cands.reserve(k);
    for (size_t i = 0; i < k; ++i) cands.push_back(bucket_hash(key, seeds[i], B));
    return cands;
}

// Placement outputs:
// table[bucket][slot] = key, or -1 empty
// pos[key] = {bucket, slot}, or {-1,-1} if not placed
struct CuckooTable {
    size_t B = 0;
    size_t d = 0;
    size_t k = 0;
    std::vector<std::vector<int64_t>> table;
    std::vector<std::pair<int32_t,int32_t>> pos; // size num_keys
};

// Bucketed cuckoo insert (deterministic kicking):
// - try any empty slot in candidate buckets (first-fit)
// - else kick out a deterministic slot in a deterministic candidate bucket
// - repeat up to max_kicks
inline bool cuckoo_insert_bucketed(
    CuckooTable& T,
    size_t key,
    const std::vector<uint64_t>& seeds,
    uint64_t kick_seed,
    size_t max_kicks
) {
    const auto cands = get_candidate_buckets(key, T.k, T.B, seeds);

    // 1) direct empty slot
    for (size_t bi = 0; bi < cands.size(); ++bi) {
        size_t b = cands[bi];
        for (size_t s = 0; s < T.d; ++s) {
            if (T.table[b][s] == -1) {
                T.table[b][s] = static_cast<int64_t>(key);
                T.pos[key] = {static_cast<int32_t>(b), static_cast<int32_t>(s)};
                return true;
            }
        }
    }

    // 2) kicking chain
    size_t cur_key = key;
    size_t cur_b = cands[ splitmix64(static_cast<uint64_t>(key) ^ kick_seed) % T.k ];

    for (size_t kick = 0; kick < max_kicks; ++kick) {
        // choose deterministic slot to evict from cur_b
        size_t evict_slot = static_cast<size_t>(
            splitmix64(static_cast<uint64_t>(cur_key) ^ (kick_seed + 0x1000003ULL * kick)) % T.d
        );

        int64_t evicted = T.table[cur_b][evict_slot];
        // place cur_key
        T.table[cur_b][evict_slot] = static_cast<int64_t>(cur_key);
        T.pos[cur_key] = {static_cast<int32_t>(cur_b), static_cast<int32_t>(evict_slot)};

        // if evicted slot was empty (shouldn't happen here), done
        if (evicted == -1) return true;

        // next key to place
        cur_key = static_cast<size_t>(evicted);
        T.pos[cur_key] = {-1, -1};

        // choose next bucket among its candidates, but avoid staying in same bucket if possible
        auto next_cands = get_candidate_buckets(cur_key, T.k, T.B, seeds);
        size_t pick = static_cast<size_t>(
            splitmix64(static_cast<uint64_t>(cur_key) ^ (kick_seed + 0x9e3779b97f4a7c15ULL + kick)) % T.k
        );
        size_t next_b = next_cands[pick];

        if (next_b == cur_b) {
            // try to pick a different candidate deterministically
            for (size_t t = 0; t < T.k; ++t) {
                size_t alt = next_cands[(pick + t) % T.k];
                if (alt != cur_b) { next_b = alt; break; }
            }
        }
        cur_b = next_b;

        // see if cur_b has an empty slot now
        for (size_t s = 0; s < T.d; ++s) {
            if (T.table[cur_b][s] == -1) {
                T.table[cur_b][s] = static_cast<int64_t>(cur_key);
                T.pos[cur_key] = {static_cast<int32_t>(cur_b), static_cast<int32_t>(s)};
                return true;
            }
        }
    }

    return false;
}

// Build placement for keys [0..num_keys-1], using replication like vectorized-batchpir
// Each key is replicated to k buckets
inline CuckooTable build_cuckoo_table_bucketed(
    size_t num_keys,
    size_t B,
    size_t d,
    size_t k,
    size_t max_kicks,
    const std::vector<uint64_t>& seeds,
    uint64_t kick_seed
) {
    if (B == 0 || d == 0 || k == 0) throw std::invalid_argument("B/d/k must be >0");

    CuckooTable T;
    T.B = B; T.d = d; T.k = k;
    T.table.assign(B, std::vector<int64_t>(d, -1));
    T.pos.assign(num_keys, {-1, -1});

    // Replicate each key to k buckets
    for (size_t key = 0; key < num_keys; ++key) {
        // Get candidate buckets using the string-based hash function
        std::vector<size_t> candidates = get_candidate_buckets(key, k, B);
        
        // Add key to all candidate buckets
        bool placed = false;
        for (size_t i = 0; i < candidates.size(); ++i) {
            size_t b = candidates[i];
            
            // Find an empty slot in the bucket
            for (size_t s = 0; s < d; ++s) {
                if (T.table[b][s] == -1) {
                    T.table[b][s] = static_cast<int64_t>(key);
                    
                    // Record the placement for each key
                    if (!placed) {
                        T.pos[key] = {static_cast<int32_t>(b), static_cast<int32_t>(s)};
                        placed = true;
                    }
                    break;
                }
            }
        }
        
        // Ensure each key is placed at least once
        if (!placed) {
            // Find any empty slot in any bucket
            for (size_t b = 0; b < B && !placed; ++b) {
                for (size_t s = 0; s < d && !placed; ++s) {
                    if (T.table[b][s] == -1) {
                        T.table[b][s] = static_cast<int64_t>(key);
                        T.pos[key] = {static_cast<int32_t>(b), static_cast<int32_t>(s)};
                        placed = true;
                    }
                }
            }
        }
    }

    return T;
}

} // namespace utils

#endif // UTILS_H