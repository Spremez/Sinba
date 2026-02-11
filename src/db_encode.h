#ifndef DB_ENCODE_H
#define DB_ENCODE_H

#include <iostream>
#include <iomanip>
#include <vector>
#include <cmath>
#include <cstdint>
#include <algorithm>
#include <memory>
#include <random>
#include "seal/seal.h"

using namespace std;
using namespace seal;

// ============================================================================
// 数据类型定义
// ============================================================================
typedef vector<uint64_t> PlainVector;           // 明文槽向量 (poly_degree 个槽)
typedef vector<PlainVector> PlainMatrix;        // 明文矩阵 (展平存储)
typedef vector<seal::Plaintext> NTTPlainMatrix; // NTT 格式的明文矩阵
typedef vector<vector<uint64_t>> RawDB;         // 原始数据库 (每个 entry 是多个 chunk)

// ============================================================================
// Single Query 数据库参数结构
// ============================================================================
struct SingleQueryParams {
    // 数据库参数
    size_t num_entries;         // 数据库条目数 (如 2^20)
    size_t payload_size;        // 每个条目的 payload 大小 (bytes)
    size_t plaintext_bits;      // 明文模数的有效位数
    size_t poly_degree;         // 多项式度数 (ring dimension)
    
    // 计算得出的参数
    size_t row_size;            // = poly_degree / 2
    size_t slots_per_entry;     // = ceil(payload_size * 8 / (plaintext_bits - 1))
    size_t entries_per_plaintext;  // 每个明文容纳 1024 条目
    size_t num_plaintexts_per_chunk_pair;  // 每个 chunk 组需要的明文数
    size_t num_chunk_pairs;     // chunk 组数量 = ceil(slots_per_entry / 8)
    
    // 第一维 BSGS 参数 (对应列方向)
    size_t dim1_size;           // = num_plaintexts_per_chunk_pair
    size_t dim1_n1;             // baby step
    size_t dim1_n2;             // giant step
    
    // 第二维 BSGS 参数 (对应行方向)
    size_t dim2_size;           // = num_chunk_pairs
    size_t dim2_n1;             // baby step
    size_t dim2_n2;             // giant step
    
    SingleQueryParams() : num_entries(0), payload_size(0), plaintext_bits(0), poly_degree(0),
                          row_size(0), slots_per_entry(0), entries_per_plaintext(0),
                          num_plaintexts_per_chunk_pair(0), num_chunk_pairs(0),
                          dim1_size(0), dim1_n1(0), dim1_n2(0),
                          dim2_size(0), dim2_n1(0), dim2_n2(0) {}
    
    void print() const {
        cout << "╔═══════════════════════════════════════════════════════════════╗" << endl;
        cout << "║              Single Query 数据库参数                          ║" << endl;
        cout << "╠═══════════════════════════════════════════════════════════════╣" << endl;
        cout << "║  数据库条目数         : " << setw(36) << num_entries << " ║" << endl;
        cout << "║  Payload 大小 (bytes) : " << setw(36) << payload_size << " ║" << endl;
        cout << "║  明文有效位数         : " << setw(36) << plaintext_bits << " ║" << endl;
        cout << "║  多项式度数           : " << setw(36) << poly_degree << " ║" << endl;
        cout << "╠═══════════════════════════════════════════════════════════════╣" << endl;
        cout << "║  Row size             : " << setw(36) << row_size << " ║" << endl;
        cout << "║  Slots per entry      : " << setw(36) << slots_per_entry << " ║" << endl;
        cout << "║  Entries per plaintext: " << setw(36) << entries_per_plaintext << " ║" << endl;
        cout << "║  Plaintexts per chunk : " << setw(36) << num_plaintexts_per_chunk_pair << " ║" << endl;
        cout << "║  Chunk pairs          : " << setw(36) << num_chunk_pairs << " ║" << endl;
        cout << "╠═══════════════════════════════════════════════════════════════╣" << endl;
        cout << "║  第一维 (列): size=" << setw(5) << dim1_size 
             << ", n1=" << setw(4) << dim1_n1 << ", n2=" << setw(4) << dim1_n2 
             << "                 ║" << endl;
        cout << "║  第二维 (行): size=" << setw(5) << dim2_size 
             << ", n1=" << setw(4) << dim2_n1 << ", n2=" << setw(4) << dim2_n2 
             << "                 ║" << endl;
        cout << "║  明文矩阵大小: " << dim2_size << " x " << dim1_size 
             << " = " << setw(10) << (dim2_size * dim1_size) << " 个明文          ║" << endl;
        cout << "╚═══════════════════════════════════════════════════════════════╝" << endl;
    }
};

// ============================================================================
// Batch Query 数据库参数结构
// ============================================================================
struct BatchPIRParams {
    size_t num_entries = 0;
    size_t batch_size = 0;
    size_t payload_size = 0;
    size_t plaintext_bits = 0;

    double cuckoo_factor = 1.5;
    size_t num_hash_funcs = 3;
    size_t max_attempts = 0; // 这里用作 max_kicks

    size_t poly_degree = 0;

    // derived
    size_t B = 0;
    size_t d = 0;
    size_t d1 = 0;
    size_t g = 0;
    size_t d2 = 0;
    size_t slots_per_entry = 0;
    size_t rows_per_plaintext = 0;
    size_t num_matrices = 0;

    // BSGS
    size_t d2_n1 = 0, d2_n2 = 0; // dim1 for slot stage (size d2)
    size_t n1 = 0, n2 = 0;       // dim2 for col stage (size rows_per_plaintext)

    // deterministic hash seeds (must be same for encoder & client)
    std::array<uint64_t, 3> hash_seeds { 0xA5A5A5A5A5A5A5A5ULL,
                                        0x0123456789ABCDEFULL,
                                        0xF00DF00DF00DF00DULL };
    uint64_t kick_seed = 0xC001D00DC001D00DULL;

     void print() const {
        std::cout << "\n[BatchPIRParams]\n";
        std::cout << "  num_entries=" << num_entries
                  << " batch_size=" << batch_size
                  << " payload_size=" << payload_size
                  << " plaintext_bits=" << plaintext_bits << "\n";
        std::cout << "  B=" << B << " d=" << d
                  << " d1=" << d1 << " d2=" << d2
                  << " g=" << g << " num_matrices=" << num_matrices << "\n";
        std::cout << "  slots_per_entry=" << slots_per_entry
                  << " rows_per_plaintext=" << rows_per_plaintext << "\n";
        std::cout << "  d2_n1=" << d2_n1 << " d2_n2=" << d2_n2
                  << " n1=" << n1 << " n2=" << n2 << "\n";
        std::cout << "  cuckoo_factor=" << cuckoo_factor
                  << " num_hash_funcs=" << num_hash_funcs
                  << " max_attempts=" << max_attempts << "\n";
        std::cout << "  hash_seeds=[" << std::hex
                  << hash_seeds[0] << ", " << hash_seeds[1] << ", " << hash_seeds[2]
                  << std::dec << "] kick_seed=" << std::hex << kick_seed << std::dec << "\n";
    }
};

// ============================================================================
// DatabaseEncoder 类 - 数据库编码器
// ============================================================================
class DatabaseEncoder {
public:
    DatabaseEncoder() = default;
    
    // ========================================================================
    // SEAL 上下文初始化
    // ========================================================================
    void init_seal_context(shared_ptr<SEALContext> context);
    
    bool is_seal_context_initialized() const { return seal_context_ != nullptr; }
    
    // ========================================================================
    // Single Query 模式
    // ========================================================================
    void set_single_query_params(size_t num_entries, size_t payload_size_bytes, 
                                  size_t plaintext_bits,
                                  size_t dim1_n1, size_t dim1_n2,
                                  size_t dim2_n1, size_t dim2_n2);
    
    PlainMatrix encode_database_single_query();
    NTTPlainMatrix encode_database_single_query_ntt();
    NTTPlainMatrix convert_to_ntt(const PlainMatrix& plain_matrix);
    
    bool verify_single_query_encode(const PlainMatrix& encoded_db, 
                                    size_t entry_idx, size_t chunk_idx);
    bool verify_single_query_encode_ntt(const NTTPlainMatrix& encoded_db,
                                        size_t entry_idx, size_t chunk_idx);
    
    const SingleQueryParams& get_single_query_params() const { return sq_params_; }
    
    // ========================================================================
    // Batch Query 模式
    // ========================================================================
    void set_batch_pir_params(size_t num_entries, size_t batch_size, size_t payload_size_bytes,
                              size_t plaintext_bits, double cuckoo_factor = 1.5,
                              size_t num_hash_funcs = 3, size_t max_attempts = 100);
    
    PlainMatrix encode_database_batch_query();
    NTTPlainMatrix encode_database_batch_query_ntt();
    
    bool verify_batch_query_encode(const PlainMatrix& encoded_db, 
                                   size_t entry_idx, size_t chunk_idx);
    bool verify_batch_query_encode_ntt(const NTTPlainMatrix& encoded_db,
                                       size_t entry_idx, size_t chunk_idx);
    
    const BatchPIRParams& get_batch_pir_params() const { return bp_params_; }
    
    // ========================================================================
    // 通用方法
    // ========================================================================
    void generate_random_database();
    const RawDB& get_raw_database() const { return raw_db_; }

    // Deterministic PRG-backed DB access (used automatically when raw_db_ is not materialized)
    // value_bits controls the output range: return in [0, 2^{value_bits})
    uint64_t get_value(size_t entry_idx, size_t chunk_idx, size_t value_bits) const;
    
    shared_ptr<SEALContext> get_seal_context() const { return seal_context_; }
    shared_ptr<BatchEncoder> get_batch_encoder() const { return batch_encoder_; }
    
    // ========================================================================
    // 辅助函数
    // ========================================================================
    static PlainVector rotate_slots(const PlainVector& v, size_t rotation);
    static void apply_bsgs_prerotation_batch_matrix(PlainMatrix& matrix, size_t matrix_base, size_t R,size_t d2,size_t d2_n1,size_t n1,size_t poly_degree);
    
private:
    size_t poly_degree_ = 0;
    uint64_t plain_modulus_ = 0;
    
    SingleQueryParams sq_params_;
    BatchPIRParams bp_params_;
    RawDB raw_db_;

    // If raw_db_ is empty, we synthesize DB values via splitmix64 PRG for reproducibility and low memory.
    bool use_prg_db_ = false;

    // If true, raw_db_ may be left empty and values are generated on-demand via a PRG.
    // This keeps memory usage reasonable for large num_entries / payload sizes.
    bool prg_db_enabled_ = false;
    uint64_t prg_seed_ = 0xBADC0FFEE0DDF00DULL;
    PlainMatrix last_plain_matrix_;
    
    shared_ptr<SEALContext> seal_context_;
    shared_ptr<BatchEncoder> batch_encoder_;
    shared_ptr<Evaluator> evaluator_;
};

#endif // DB_ENCODE_H