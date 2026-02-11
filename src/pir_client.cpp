#include "pir_client.h"
#include "utils.h"
#include <chrono>

// ============================================================================
// 初始化
// ============================================================================

void PIRClient::init(shared_ptr<SEALContext> context) {
    if (!context) {
        throw invalid_argument("SEAL context cannot be null");
    }
    
    context_ = context;
    
    auto context_data = context_->first_context_data();
    if (!context_data) {
        throw runtime_error("Invalid SEAL context");
    }
    
    if (!context_data->qualifiers().using_batching) {
        throw runtime_error("Batching is not supported with the given parameters");
    }
    
    const auto& parms = context_data->parms();
    poly_degree_ = parms.poly_modulus_degree();
    plain_modulus_ = parms.plain_modulus().value();
    row_size_ = poly_degree_ / 2;
    
    batch_encoder_ = make_shared<BatchEncoder>(*context_);
    evaluator_ = make_shared<Evaluator>(*context_);
    
    sq_params_set_ = false;
    
    cout << "\n[PIRClient 初始化]" << endl;
    cout << "  ✓ poly_modulus_degree: " << poly_degree_ << endl;
    cout << "  ✓ plain_modulus: " << plain_modulus_ << endl;
    cout << "  ✓ slot_count: " << batch_encoder_->slot_count() << endl;
}

// ============================================================================
// 密钥管理
// ============================================================================
void PIRClient::generate_keys() {
    cout << "\n[生成密钥]" << endl;
    
    auto start = chrono::high_resolution_clock::now();
    
    keygen_ = make_shared<KeyGenerator>(*context_);
    secret_key_ = keygen_->secret_key();
    keygen_->create_public_key(public_key_);
    keygen_->create_relin_keys(relin_keys_);
    
    encryptor_ = make_shared<Encryptor>(*context_, public_key_);
    decryptor_ = make_shared<Decryptor>(*context_, secret_key_);
    
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);
    
    cout << "  ✓ 密钥生成完成 (" << duration.count() << " ms)" << endl;
}

void PIRClient::generate_galois_keys(const vector<int>& steps) {
    cout << "\n[生成 Galois Keys]" << endl;
    cout << "  旋转步长: ";
    for (int s : steps) cout << s << " ";
    cout << endl;
    
    auto start = chrono::high_resolution_clock::now();
    
    keygen_->create_galois_keys(steps, galois_keys_);
    
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);
    
    cout << "  ✓ Galois Keys 生成完成 (" << duration.count() << " ms)" << endl;
}

// ============================================================================
// Single Query 模式
// ============================================================================
void PIRClient::set_single_query_params(const SingleQueryParams& params) {
    sq_params_ = params;
    sq_params_set_ = true;
    
    cout << "\n[设置 Single Query 参数]" << endl;
    sq_params_.print();
}

void PIRClient::set_single_query_params(size_t num_entries, size_t payload_size,
                                        size_t plaintext_bits,
                                        size_t dim1_n1, size_t dim1_n2,
                                        size_t dim2_n1, size_t dim2_n2) {
    if (!context_) {
        throw runtime_error("Client not initialized. Call init() first.");
    }
    
    sq_params_.num_entries = num_entries;
    sq_params_.payload_size = payload_size;
    sq_params_.plaintext_bits = plaintext_bits;
    sq_params_.poly_degree = poly_degree_;
    sq_params_.row_size = poly_degree_ / 2;
    
    // 计算每个条目需要的槽数 (每个 slot 存 plaintext_bits)
    size_t bits_per_slot = plaintext_bits;
    size_t payload_bits = payload_size * 8;
    sq_params_.slots_per_entry = (payload_bits + bits_per_slot - 1) / bits_per_slot;
    
    sq_params_.entries_per_plaintext = 1 << 10;
    
    size_t total_chunks = sq_params_.slots_per_entry;
    sq_params_.num_chunk_pairs = (total_chunks + 7) / 8;
    
    sq_params_.num_plaintexts_per_chunk_pair = (num_entries + sq_params_.entries_per_plaintext - 1) 
                                               / sq_params_.entries_per_plaintext;
    
    sq_params_.dim1_size = sq_params_.num_plaintexts_per_chunk_pair;
    sq_params_.dim2_size = sq_params_.num_chunk_pairs;
    
    sq_params_.dim1_n1 = dim1_n1;
    sq_params_.dim1_n2 = dim1_n2;
    sq_params_.dim2_n1 = dim2_n1;
    sq_params_.dim2_n2 = dim2_n2;
    
    sq_params_set_ = true;
    
    cout << "\n[设置 Single Query 参数]" << endl;
    sq_params_.print();
}

SingleQueryResult PIRClient::generate_single_query(size_t entry_idx) {
    if (!sq_params_set_) {
        throw runtime_error("Single Query parameters not set. Call set_single_query_params() first.");
    }
    
    if (!encryptor_) {
        throw runtime_error("Keys not generated. Call generate_keys() first.");
    }
    
    // 直接根据entry idx计算idx1和idx2
    // idx = idx2 * 1024 + idx1
    size_t idx1 = entry_idx % 1024;
    size_t idx2 = entry_idx / 1024;
    
    SingleQueryResult result;
    result.target_entry_idx = entry_idx;
    result.chunk_idx = 0; // 默认返回所有chunk，设置为0
    
    // Step 1: 槽选择 - 使用新的create_slot_selection函数
    result.slot_selection = create_slot_selection(idx1, true);
    
    // Step 2: 列选择 - 实现新的colquery生成逻辑
    vector<uint64_t> slots(poly_degree_, 0ULL);
    
    // 将（idx1+idx2）%1024, （idx1+idx2+1024）%1024, ..., （idx1+idx2+7168）%1024设为1
    for (size_t i = 0; i < 8; i++) {
        size_t pos = (idx1 + idx2 + i * 1024) % poly_degree_;
        slots[pos] = 1;
    }
    
    Plaintext pt;
    batch_encoder_->encode(slots, pt);
    encryptor_->encrypt(pt, result.dim1_query);
    
    return result;
}

vector<uint64_t> PIRClient::decrypt_single_response(const Ciphertext& response, const SingleQueryResult& query) {
    if (!decryptor_) {
        throw runtime_error("Keys not generated. Call generate_keys() first.");
    }
    
    Plaintext pt;
    decryptor_->decrypt(response, pt);
    
    vector<uint64_t> all_slots;
    batch_encoder_->decode(pt, all_slots);
    
    // 直接返回所有非零值
    vector<uint64_t> non_zero_values;
    for (uint64_t slot : all_slots) {
        if (slot != 0) {
            non_zero_values.push_back(slot);
        }
    }
    
    return non_zero_values;
}

Ciphertext PIRClient::create_slot_selection(size_t idx1, bool both_rows) {
    if (!encryptor_) {
        throw runtime_error("Keys not generated. Call generate_keys() first.");
    }
    
    // BGV 批处理模式中，每个密文包含两行，每行 poly_degree_/2 个槽，总共 poly_degree_ 个槽
    vector<uint64_t> slots(poly_degree_, 0ULL);
    
    // 实现新的slotquery生成逻辑：将明文槽idx1, idx1+1024, ..., idx1+7168设为1
    // 1024是步长，7168=7*1024，共8个位置
    for (size_t i = 0; i < 8; i++) {
        size_t pos = idx1 + i * 1024;
        if (pos < poly_degree_) {
            slots[pos] = 1;
        }
    }
    
    Plaintext pt;
    batch_encoder_->encode(slots, pt);
    
    Ciphertext ct;
    encryptor_->encrypt(pt, ct);
    
    return ct;
}

// ============================================================================// Batch Query 模式// ============================================================================
void PIRClient::set_batch_pir_params(const BatchPIRParams& params) {
    bp_params_ = params;
    bp_params_set_ = true;
    
    cout << "\n[设置 Batch Query 参数]" << endl;
    bp_params_.print();
}

void PIRClient::set_batch_pir_params(size_t num_entries, size_t batch_size, size_t payload_size,
                                    size_t plaintext_bits, double cuckoo_factor,
                                    size_t num_hash_funcs, size_t max_attempts) {
    if (!context_) {
        throw runtime_error("Client not initialized. Call init() first.");
    }
    
    bp_params_.num_entries = num_entries;
    bp_params_.batch_size = batch_size;
    bp_params_.payload_size = payload_size;
    bp_params_.plaintext_bits = plaintext_bits;
    bp_params_.poly_degree = poly_degree_;
    bp_params_.cuckoo_factor = cuckoo_factor;
    bp_params_.num_hash_funcs = num_hash_funcs;
    bp_params_.max_attempts = max_attempts;
    
     // 计算 B / slots_per_entry / rows_per_plaintext 同 encoder
    bp_params_.B = static_cast<size_t>(ceil(batch_size * cuckoo_factor));
    bp_params_.slots_per_entry = (payload_size * 8 + plaintext_bits - 1) / plaintext_bits;
    bp_params_.rows_per_plaintext = (bp_params_.slots_per_entry + 1) / 2;

    // Calculate d based on replication like vectorized-batchpir
    // Same logic as server-side
    size_t total_entries_after_replication = num_entries * num_hash_funcs;
    size_t theoretical_max_bucket_size = (total_entries_after_replication + bp_params_.B - 1) / bp_params_.B;
    if (theoretical_max_bucket_size == 0) theoretical_max_bucket_size = 1;

    vector<uint64_t> seeds = { bp_params_.hash_seeds[0], bp_params_.hash_seeds[1], bp_params_.hash_seeds[2] };

    // Build cuckoo table with the theoretical maximum bucket size
    utils::CuckooTable T;
    try {
        T = utils::build_cuckoo_table_bucketed(
            num_entries, bp_params_.B, theoretical_max_bucket_size, num_hash_funcs,
            std::max<size_t>(max_attempts, 500),
            seeds, bp_params_.kick_seed
        );
    } catch (const std::exception& e) {
        throw runtime_error("Client failed to build cuckoo placement: " + std::string(e.what()));
    }

    // Calculate actual maximum bucket size
    size_t actual_max_bucket_size = 0;
    for (size_t b = 0; b < T.B; ++b) {
        size_t bucket_size = 0;
        for (size_t s = 0; s < theoretical_max_bucket_size; ++s) {
            if (T.table[b][s] != -1) {
                bucket_size++;
            }
        }
        if (bucket_size > actual_max_bucket_size) {
            actual_max_bucket_size = bucket_size;
        }
    }

    // Set d to the actual maximum bucket size
    bp_params_.d = actual_max_bucket_size;
    bp_cuckoo_ = T;
    bp_cuckoo_ready_ = true;
    cerr << "[INFO] Client: Set d to actual maximum bucket size: " << bp_params_.d << " (theoretical was: " << theoretical_max_bucket_size << ")" << endl;

    bp_params_.d1 = static_cast<size_t>(ceil(sqrt((double)bp_params_.d)));
    if (bp_params_.d1 == 0) bp_params_.d1 = 1;

    const size_t S = poly_degree_ / 2; // 4096
    bp_params_.g = S / bp_params_.d1;
    if (bp_params_.g == 0) throw runtime_error("g=0");

    bp_params_.d2 = (bp_params_.d + bp_params_.d1 - 1) / bp_params_.d1;
    if (bp_params_.d1 * bp_params_.d2 < bp_params_.d) bp_params_.d2++;

    bp_params_.num_matrices = (bp_params_.B + bp_params_.g - 1) / bp_params_.g;

    // BSGS
    // Find d2_n1 and d2_n2 such that:
    // 1. d2_n1 * d2_n2 > d2
    // 2. d2_n1 + rows_per_plaintext * d2_n2 is minimized
    size_t best_d2_n1 = 1;
    size_t best_d2_n2 = bp_params_.d2;
    size_t min_cost = best_d2_n1 + bp_params_.rows_per_plaintext * best_d2_n2;
    
    // Iterate all possible d2_n1 values to find the optimal solution
    // We only need to check up to d2 since d2_n1 > d2 would result in d2_n2 = 1
    // but cost would be d2_n1 + rows_per_plaintext, which is likely higher than smaller values
    for (size_t candidate_d2_n1 = 1; candidate_d2_n1 <= bp_params_.d2; ++candidate_d2_n1) {
        size_t candidate_d2_n2 = (bp_params_.d2 + candidate_d2_n1 - 1) / candidate_d2_n1;
        
        // Ensure d2_n1 * d2_n2 > d2
        if (candidate_d2_n1 * candidate_d2_n2 <= bp_params_.d2) {
            candidate_d2_n2++;
        }
        
        // Calculate cost
        size_t cost = candidate_d2_n1 + bp_params_.rows_per_plaintext * candidate_d2_n2;
        
        // Update best if current cost is lower
        if (cost < min_cost) {
            min_cost = cost;
            best_d2_n1 = candidate_d2_n1;
            best_d2_n2 = candidate_d2_n2;
        }
    }
    
    bp_params_.d2_n1 = best_d2_n1;
    bp_params_.d2_n2 = best_d2_n2;
    cerr << "[INFO] Client: Optimized d2_n1=" << bp_params_.d2_n1 << ", d2_n2=" << bp_params_.d2_n2 
         << ", cost=" << min_cost << " (d2=" << bp_params_.d2 << ")" << endl;

    bp_params_.n1 = static_cast<size_t>(sqrt((double)bp_params_.rows_per_plaintext));
    if (bp_params_.n1 == 0) bp_params_.n1 = 1;
    bp_params_.n2 = (bp_params_.rows_per_plaintext + bp_params_.n1 - 1) / bp_params_.n1;

    bp_params_set_ = true;
    bp_params_.print();
}

BatchQueryResult PIRClient::generate_batch_queries(const vector<size_t>& target_indices) {
   if (!bp_params_set_) throw runtime_error("Batch params not set.");
    if (!encryptor_) throw runtime_error("Keys not generated.");
    if (!bp_cuckoo_ready_) throw runtime_error("Cuckoo placement not ready.");
    if (target_indices.size() != bp_params_.batch_size) throw invalid_argument("target size != batch_size");

    BatchQueryResult result;
    result.target_entry_indices = target_indices;
    result.batch_size = bp_params_.batch_size;
    result.g = bp_params_.g;
    result.d1 = bp_params_.d1;
    result.d2 = bp_params_.d2;

    const size_t N = poly_degree_;
    const size_t S = N / 2;
    const size_t g = bp_params_.g;
    const size_t d1 = bp_params_.d1;
    const size_t M = bp_params_.num_matrices;

    // 预先算每个 target 的 (bucket, t)
    struct Loc {
    size_t  key;
    int32_t b;
    int32_t t;
};

vector<Loc> locs;
locs.reserve(target_indices.size());

for (size_t key : target_indices) {
    if (key >= bp_cuckoo_.pos.size()) {
        throw runtime_error("target key out of range");
    }

    auto p = bp_cuckoo_.pos[key]; // pair<int32_t,int32_t>
    if (p.first < 0 || p.second < 0) {
        throw runtime_error("target not placed in cuckoo table");
    }

    Loc L;
    L.key = key;
    L.b   = p.first;
    L.t   = p.second;
    locs.push_back(L);
}

    // 对每个矩阵 m 生成 1 个 slot_query 和 1 个 col_query
    for (size_t m = 0; m < M; ++m) {
        vector<uint64_t> slot_vec(N, 0ULL);

        // slot_query：把本矩阵覆盖的 g 个桶里，命中的 off 置 1（两行 lane 都置 1）
        for (const auto& L : locs) {
            size_t bucket = static_cast<size_t>(L.b);
            if (bucket < m * g || bucket >= (m + 1) * g) continue;
            size_t b_local = bucket - m * g;

            size_t t = static_cast<size_t>(L.t);
            size_t off = t % d1;

            size_t pos0 = 0 * (g * d1) + b_local * d1 + off;
            size_t pos1 = 1 * (g * d1) + b_local * d1 + off;
            if (pos0 < N) slot_vec[pos0] = 1;
            if (pos1 < N) slot_vec[pos1] = 1;
        }

        Plaintext pt_slot;
        batch_encoder_->encode(slot_vec, pt_slot);
        Ciphertext ct_slot;
        encryptor_->encrypt(pt_slot, ct_slot);
        result.slot_selections.push_back(std::move(ct_slot));

        //col-query
       vector<uint64_t> col_vec(poly_degree_, 0ULL);

const size_t N = poly_degree_;
const size_t S = N / 2;
const size_t g  = bp_params_.g;
const size_t d1 = bp_params_.d1;
const size_t d2 = bp_params_.d2;

// 对本矩阵 m 覆盖的桶组，给命中的目标 entry 置位
for (const auto& L : locs) {
    size_t bucket = static_cast<size_t>(L.b);
    if (bucket < m * g || bucket >= (m + 1) * g) continue;

    size_t b_local = bucket - m * g;
    size_t t = static_cast<size_t>(L.t);

    size_t idx1 = t % d1;
    size_t idx2 = t / d1;          // 0..d2-1 (理论上)
    if (idx2 >= d2) continue;      // 防御：t 可能落在 padding 区

    size_t u = (idx1 + idx2) % d2; // 你的定义

    size_t pos0 = b_local * d1 + u;      // lane 0
    size_t pos1 = S + b_local * d1 + u;  // lane 1 (复制到剩余 4096)

    if (pos0 < N) col_vec[pos0] = 1;
    if (pos1 < N) col_vec[pos1] = 1;
}

Plaintext pt_col;
batch_encoder_->encode(col_vec, pt_col);
Ciphertext ct_col;
encryptor_->encrypt(pt_col, ct_col);
result.col_queries.push_back(std::move(ct_col));
    }

    return result;
}

vector<vector<uint64_t>> PIRClient::decrypt_batch_responses(const vector<Ciphertext>& responses, const BatchQueryResult& query) {
    if (!decryptor_) {
        throw runtime_error("Keys not generated. Call generate_keys() first.");
    }
    
    if (responses.size() != query.col_queries.size()) {
        throw invalid_argument("Responses size does not match queries size.");
    }
    
    vector<vector<uint64_t>> results;
    
    cout << "\n[解密 Batch Query 响应]" << endl;
    cout << "  解密 " << responses.size() << " 个响应..." << endl;
    
    for (size_t i = 0; i < responses.size(); ++i) {
        const Ciphertext& response = responses[i];
        
        Plaintext pt;
        decryptor_->decrypt(response, pt);
        
        vector<uint64_t> all_slots;
        batch_encoder_->decode(pt, all_slots);
        
        // 提取非零值作为结果
        vector<uint64_t> non_zero_values;
        for (uint64_t slot : all_slots) {
            if (slot != 0) {
                non_zero_values.push_back(slot);
            }
        }
        
        results.push_back(non_zero_values);
    }
    
    cout << "  ✓ 解密完成" << endl;
    
    return results;
}

void PIRClient::print_params() const {
    cout << "\n╔════════════════════════════════════════════════════════════════╣" << endl;
    cout << "║                    PIRClient 参数                              ║" << endl;
    cout << "╠════════════════════════════════════════════════════════════════╣" << endl;
    cout << "║  poly_degree    : " << setw(44) << poly_degree_ << " ║" << endl;
    cout << "║  row_size       : " << setw(44) << row_size_ << " ║" << endl;
    cout << "║  plain_modulus  : " << setw(44) << plain_modulus_ << " ║" << endl;
    cout << "║  slot_count     : " << setw(44) << batch_encoder_->slot_count() << " ║" << endl;
    cout << "║  Single Query   : " << setw(44) << (sq_params_set_ ? "已配置" : "未配置") << " ║" << endl;
    cout << "║  Batch Query    : " << setw(44) << (bp_params_set_ ? "已配置" : "未配置") << " ║" << endl;
    if (bp_params_set_) {
        cout << "║  Batch Size     : " << setw(44) << bp_params_.batch_size << " ║" << endl;
        cout << "║  Num Matrices   : " << setw(44) << bp_params_.num_matrices << " ║" << endl;
    }
    cout << "╚════════════════════════════════════════════════════════════════╝" << endl;
}

