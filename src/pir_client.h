#ifndef PIR_CLIENT_H
#define PIR_CLIENT_H

#include "db_encode.h"
#include "utils.h"
#include <memory>

using namespace std;
using namespace seal;

// ============================================================================// Single Query 查询结构// ============================================================================
struct SingleQueryResult {
    Ciphertext dim1_query;       // 列选择查询
    Ciphertext slot_selection;   // 槽选择查询
    
    size_t target_entry_idx;
    size_t chunk_idx;            // 数据块索引
    size_t dim1_baby_step;
    size_t dim1_giant_step;
    size_t slot_position;
    size_t dim1_n1;
    size_t dim2_size;
};

// ============================================================================// Batch Query 查询结构// ============================================================================
struct BatchQueryResult {
    vector<Ciphertext> col_queries;       // 列选择查询
    vector<Ciphertext> slot_selections;   // 槽选择查询
    
    vector<size_t> target_entry_indices;  // 目标条目索引列表
    vector<size_t> bucket_indices;        // 桶索引列表
    vector<size_t> slot_positions;        // 槽位置列表
    
    size_t batch_size;                    // 批处理大小
    size_t g;                             // 每个矩阵对应的桶数
    size_t d1;                            // 每桶每列占用的slot数
    size_t d2;                            // 列数
};

// ============================================================================// PIRClient 类 - PIR 客户端// ============================================================================
class PIRClient {
public:
    PIRClient() = default;
    
    void init(shared_ptr<SEALContext> context);
    
    // ========== 密钥管理 ==========
    void generate_keys();
    void generate_galois_keys(const vector<int>& steps);
    
    const PublicKey& get_public_key() const { return public_key_; }
    const GaloisKeys& get_galois_keys() const { return galois_keys_; }
    const RelinKeys& get_relin_keys() const { return relin_keys_; }
    const SecretKey& get_secret_key() const { return secret_key_; }
    
    // ========== Single Query 模式 ==========
    void set_single_query_params(const SingleQueryParams& params);
    void set_single_query_params(size_t num_entries, size_t payload_size,
                                 size_t plaintext_bits,
                                 size_t dim1_n1, size_t dim1_n2,
                                 size_t dim2_n1, size_t dim2_n2);
    
    const SingleQueryParams& get_single_query_params() const { return sq_params_; }
    
    SingleQueryResult generate_single_query(size_t entry_idx);
    vector<uint64_t> decrypt_single_response(const Ciphertext& response, const SingleQueryResult& query);
    
    // ========== Batch Query 模式 ==========
    void set_batch_pir_params(const BatchPIRParams& params);
    void set_batch_pir_params(size_t num_entries, size_t batch_size, size_t payload_size,
                              size_t plaintext_bits, double cuckoo_factor = 1.5,
                              size_t num_hash_funcs = 3, size_t max_attempts = 100);
    
    const BatchPIRParams& get_batch_pir_params() const { return bp_params_; }
    
    BatchQueryResult generate_batch_queries(const vector<size_t>& target_indices);
    vector<vector<uint64_t>> decrypt_batch_responses(const vector<Ciphertext>& responses, const BatchQueryResult& query);
    
    // ========== 辅助函数 ==========
    Ciphertext create_slot_selection(size_t idx1, bool both_rows = false);
    void print_params() const;
    
    shared_ptr<SEALContext> get_context() const { return context_; }
    shared_ptr<BatchEncoder> get_batch_encoder() const { return batch_encoder_; }
    
private:
    shared_ptr<SEALContext> context_;
    shared_ptr<KeyGenerator> keygen_;
    shared_ptr<BatchEncoder> batch_encoder_;
    shared_ptr<Encryptor> encryptor_;
    shared_ptr<Decryptor> decryptor_;
    shared_ptr<Evaluator> evaluator_;
    
    SecretKey secret_key_;
    PublicKey public_key_;
    GaloisKeys galois_keys_;
    RelinKeys relin_keys_;
    
    size_t poly_degree_ = 0;
    size_t row_size_ = 0;
    uint64_t plain_modulus_ = 0;
    
    SingleQueryParams sq_params_;
    BatchPIRParams bp_params_;
    bool sq_params_set_ = false;
    bool bp_params_set_ = false;
    
    // Batch PIR cuckoo table
    utils::CuckooTable bp_cuckoo_;
    bool bp_cuckoo_ready_ = false;
};

#endif // PIR_CLIENT_H

