#pragma once

#include <seal/seal.h>
#include <vector>
#include <memory>
#include <chrono>
#include "db_encode.h"
#include "pir_client.h"

using namespace seal;
using namespace std;

// ============================================================================// Single Query 响应结构// ============================================================================
struct SingleQueryResponse {
    Ciphertext response;
    
    double slot_process_time_ms;
    double col_process_time_ms;
    double total_time_ms;
    size_t num_plaintext_mults;
    size_t num_ciphertext_mults;
    size_t num_rotations;
    size_t num_relinearizations;
    
    // Slot Query 详细性能统计
    double slot_rotation_time_ms;
    double slot_mult_time_ms;
    double slot_total_time_ms;
    size_t slot_rotation_count;
    size_t slot_mult_count;
};

// ============================================================================// Batch Query 响应结构// ============================================================================
struct BatchQueryResponse {
    vector<Ciphertext> responses;
    
    double total_time_ms;
    size_t num_plaintext_mults;
    size_t num_ciphertext_mults;
    size_t num_rotations;
    size_t num_relinearizations;
    
    // 详细性能统计
    double slot_process_time_ms;
    double col_process_time_ms;
    double rotation_time_ms;
    double mult_time_ms;
    
    size_t slot_rotation_count;
    size_t slot_mult_count;
};

// ============================================================================// BSGS 参数优化结构// ============================================================================
struct BSGSParams {
    size_t n1;
    size_t n2;
};

// ============================================================================// PIRServer 类 - PIR 服务器// ============================================================================
class PIRServer {
public:
    PIRServer();
    ~PIRServer() = default;
    
    void init(shared_ptr<SEALContext> context);
    void set_client_keys(const GaloisKeys& galois_keys, const RelinKeys& relin_keys);
    
    // ========== Single Query 模式 ==========
    void set_database_single_query(const NTTPlainMatrix& ntt_db, 
                                   const SingleQueryParams& params);
    
    SingleQueryResponse process_single_query(const SingleQueryResult& query);
    
    // ========== Batch Query 模式 ==========
    void set_database_batch_query(const NTTPlainMatrix& ntt_db, 
                                 const BatchPIRParams& params);
    
    BatchQueryResponse process_batch_queries(const BatchQueryResult& query);
    
    vector<int> get_required_rotation_steps() const;
    void print_status() const;
    
private:
    shared_ptr<SEALContext> context_;
    shared_ptr<Evaluator> evaluator_;
    shared_ptr<BatchEncoder> batch_encoder_;
    
    GaloisKeys galois_keys_;
    RelinKeys relin_keys_;
    bool keys_set_ = false;
    
    NTTPlainMatrix ntt_database_;
    SingleQueryParams sq_params_;
    BatchPIRParams bp_params_;
    bool database_set_ = false;
    bool is_batch_mode_ = false;
    
    size_t poly_degree_ = 0;
    size_t row_size_ = 0;
    
    // 使用SEAL内置内存池
    MemoryPoolHandle pool_;
    
    // ========== Single Query 处理方法 ==========
    vector<Ciphertext> process_slot_query(const Ciphertext& slot_query, size_t chunk_idx);
    Ciphertext process_single_row_slot(const vector<Ciphertext>& slot_rotations, size_t row_idx);
    Ciphertext process_col_query(const Ciphertext& col_query, const vector<Ciphertext>& row_results);
    
    // ========== Batch Query 处理方法 ==========
    vector<Ciphertext> process_batch_slot_queries(const vector<Ciphertext>& slot_queries);
    vector<Ciphertext> process_batch_col_queries(const vector<Ciphertext>& col_queries, const vector<Ciphertext>& slot_results);
    
    // 通用方法
    vector<Ciphertext> generate_rotations(const Ciphertext& ct, size_t n1);
    
    Ciphertext bsgs_inner_product_plain_ref(const vector<Ciphertext>& ct_rotations,
                                            size_t db_base_idx, size_t num_plaintexts,
                                            size_t n1, size_t n2);
    
    Ciphertext bsgs_inner_product_cipher(const vector<Ciphertext>& query_rotations,
                                         const vector<Ciphertext>& data_cts,
                                         size_t n1, size_t n2);
    
    // 动态BSGS参数计算
    BSGSParams calculate_optimal_bsgs_params(size_t dim_size, size_t plaintext_matrix_rows) const;
    
    mutable size_t stat_plaintext_mults_ = 0;
    mutable size_t stat_ciphertext_mults_ = 0;
    mutable size_t stat_rotations_ = 0;
    mutable size_t stat_relinearizations_ = 0;
    
    // 详细的性能统计
    mutable double slot_rotation_time_ms_ = 0;
    mutable double slot_mult_time_ms_ = 0;
    mutable size_t slot_rotation_count_ = 0;
    mutable size_t slot_mult_count_ = 0;
    
    void reset_stats() {
        stat_plaintext_mults_ = 0;
        stat_ciphertext_mults_ = 0;
        stat_rotations_ = 0;
        stat_relinearizations_ = 0;
        slot_rotation_time_ms_ = 0;
        slot_mult_time_ms_ = 0;
        slot_rotation_count_ = 0;
        slot_mult_count_ = 0;
    }
};

