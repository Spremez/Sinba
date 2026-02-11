#include "pir_server.h"

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <chrono>

using namespace std;
using namespace seal;

// ============================================================================
// Logging macros (compile-time removable)
// PIR_SERVER_LOG_LEVEL:
//   0 = no logs (bench)
//   1 = init/one-shot logs
//   2 = verbose logs (per-query / progress)
// ============================================================================
#ifndef PIR_SERVER_LOG_LEVEL
#define PIR_SERVER_LOG_LEVEL 0
#endif

#if PIR_SERVER_LOG_LEVEL >= 1
#define PIRLOG1(x) do { std::cout << x << std::endl; } while(0)
#else
#define PIRLOG1(x) do {} while(0)
#endif

#if PIR_SERVER_LOG_LEVEL >= 2
#define PIRLOG2(x) do { std::cout << x << std::endl; } while(0)
#else
#define PIRLOG2(x) do {} while(0)
#endif

// ============================================================================
// Small helpers
// ============================================================================

// Ensure ciphertext is NTT form (returns a copy; avoids mutating input).
static inline Ciphertext ensure_ntt_form_copy(const Ciphertext &in,
                                              Evaluator &evaluator,
                                              const MemoryPoolHandle &pool)
{
    Ciphertext out(pool);
    out = in; // unavoidable copy unless caller can move
    if (!out.is_ntt_form())
    {
        evaluator.transform_to_ntt_inplace(out);
    }
    return out;
}

// Generate contiguous steps: 0..n1-1
static inline vector<int> make_contiguous_steps(size_t n1)
{
    vector<int> steps;
    steps.reserve(n1);
    for (size_t i = 0; i < n1; ++i)
    {
        steps.push_back(static_cast<int>(i));
    }
    return steps;
}

// ============================================================================
// ctor
// ============================================================================
PIRServer::PIRServer() {}

// ============================================================================
// init
// ============================================================================
void PIRServer::init(shared_ptr<SEALContext> context)
{
    if (!context) throw invalid_argument("SEAL context cannot be null");

    context_ = std::move(context);
    evaluator_ = make_shared<Evaluator>(*context_);
    batch_encoder_ = make_shared<BatchEncoder>(*context_);

    pool_ = MemoryManager::GetPool();

    poly_degree_ = context_->first_context_data()->parms().poly_modulus_degree();

    // IMPORTANT:
    // For BFV/BGV batching, slot_count == poly_modulus_degree (N).
    // Using N/2 here is CKKS intuition and will mislead your params.
    row_size_ = poly_degree_ / 2;                // == S (4096 for N=8192)

    PIRLOG1("[PIRServer] init done");
    PIRLOG1("  poly_degree: " << poly_degree_);
    PIRLOG1("  row_size: " << row_size_);
}

void PIRServer::set_client_keys(const GaloisKeys &galois_keys, const RelinKeys &relin_keys)
{
    galois_keys_ = galois_keys;
    relin_keys_ = relin_keys;
    keys_set_ = true;
    PIRLOG1("[PIRServer] client keys set");
}

// ============================================================================
// DB set
// ============================================================================
void PIRServer::set_database_single_query(const NTTPlainMatrix &ntt_db,
                                          const SingleQueryParams &params)
{
    ntt_database_ = ntt_db;
    sq_params_ = params;
    database_set_ = true;
    is_batch_mode_ = false;

    PIRLOG1("[PIRServer] single-query DB set (NTT)");
    PIRLOG1("  DB plaintexts: " << ntt_db.size());
    PIRLOG1("  matrix: " << params.dim2_size << " x " << params.dim1_size);
    PIRLOG1("  dim1 BSGS: n1=" << params.dim1_n1 << ", n2=" << params.dim1_n2);
    PIRLOG1("  dim2 BSGS: n1=" << params.dim2_n1 << ", n2=" << params.dim2_n2);
}

// ============================================================================// Batch Query 数据库设置// ============================================================================
void PIRServer::set_database_batch_query(const NTTPlainMatrix &ntt_db,
                                         const BatchPIRParams &params)
{
    ntt_database_ = ntt_db;
    bp_params_ = params;
    database_set_ = true;
    is_batch_mode_ = true;

    PIRLOG1("[PIRServer] batch-query DB set (NTT)");
    PIRLOG1("  DB plaintexts: " << ntt_db.size());
    PIRLOG1("  batch_size: " << params.batch_size);
    PIRLOG1("  num_matrices: " << params.num_matrices);
    PIRLOG1("  buckets: " << params.B);
    PIRLOG1("  max bucket size: " << params.d);
    PIRLOG1("  d1: " << params.d1 << ", g: " << params.g << ", d2: " << params.d2);
}

// ============================================================================
// rotation generation (step-based, NOT iterative rotate(1))
// rotations[i] = rotate_rows(base, i), base fixed
// base is transformed to NTT once.
// ============================================================================
vector<Ciphertext> PIRServer::generate_rotations(const Ciphertext &ct, size_t n1)
{
    // steps: 0..n1-1
    vector<int> steps = make_contiguous_steps(n1);

    // ensure base NTT once
    Ciphertext base_ntt = ensure_ntt_form_copy(ct, *evaluator_, pool_);

    vector<Ciphertext> rotations;
    rotations.reserve(steps.size());

    for (int step : steps)
    {
        Ciphertext r(pool_);

        if (step == 0)
        {
            r = base_ntt;
        }
        else
        {
            auto t0 = chrono::high_resolution_clock::now();
            evaluator_->rotate_rows(base_ntt, step, galois_keys_, r); // out-of-place
            auto t1 = chrono::high_resolution_clock::now();

            slot_rotation_time_ms_ += chrono::duration<double, milli>(t1 - t0).count();
            slot_rotation_count_++;
            stat_rotations_++;
        }

        rotations.emplace_back(std::move(r));
    }

    return rotations;
}

// ============================================================================
// main query
// ============================================================================
SingleQueryResponse PIRServer::process_single_query(const SingleQueryResult &query)
{
    if (!context_ || !evaluator_) throw runtime_error("Server not initialized. Call init() first.");
    if (!keys_set_) throw runtime_error("Client keys not set. Call set_client_keys() first.");
    if (!database_set_) throw runtime_error("Database not set. Call set_database_single_query() first.");

    reset_stats();
    PIRLOG2("[PIRServer] process_single_query start");

    auto total_start = chrono::high_resolution_clock::now();

    // Step 1: Slot Query
    auto step1_start = chrono::high_resolution_clock::now();
    vector<Ciphertext> row_results = process_slot_query(query.slot_selection, query.chunk_idx);
    auto step1_end = chrono::high_resolution_clock::now();
    double step1_time = chrono::duration<double, milli>(step1_end - step1_start).count();

    // Step 2: Col Query
    auto step2_start = chrono::high_resolution_clock::now();

    const size_t n1 = sq_params_.dim2_n1;
    const size_t num_rows = row_results.size();
    const size_t n2_actual = (num_rows + n1 - 1) / n1;

    vector<Ciphertext> col_rotations = generate_rotations(query.dim1_query, n1);
    Ciphertext response = bsgs_inner_product_cipher(col_rotations, row_results, n1, n2_actual);

    auto step2_end = chrono::high_resolution_clock::now();
    double step2_time = chrono::duration<double, milli>(step2_end - step2_start).count();

    auto total_end = chrono::high_resolution_clock::now();
    double total_time = chrono::duration<double, milli>(total_end - total_start).count();

    SingleQueryResponse result;
    result.response = std::move(response);

    result.slot_process_time_ms = step1_time;
    result.col_process_time_ms  = step2_time;
    result.total_time_ms        = total_time;

    result.num_plaintext_mults    = stat_plaintext_mults_;
    result.num_ciphertext_mults   = stat_ciphertext_mults_;
    result.num_rotations          = stat_rotations_;
    result.num_relinearizations   = stat_relinearizations_;

    // Slot Query detailed stats
    result.slot_rotation_time_ms  = slot_rotation_time_ms_;
    result.slot_mult_time_ms      = slot_mult_time_ms_;
    result.slot_total_time_ms     = step1_time;
    result.slot_rotation_count    = slot_rotation_count_;
    result.slot_mult_count        = slot_mult_count_;

    PIRLOG2("[PIRServer] done. total_ms=" << total_time
            << ", pt_mult=" << stat_plaintext_mults_
            << ", ct_mult=" << stat_ciphertext_mults_
            << ", rot=" << stat_rotations_
            << ", relin=" << stat_relinearizations_);

    return result;
}

// ============================================================================
// Step 1: Slot Query
// ============================================================================
vector<Ciphertext> PIRServer::process_slot_query(const Ciphertext &slot_query, size_t /*chunk_idx*/)
{
    const size_t n1 = sq_params_.dim1_n1;
    const size_t num_rows = sq_params_.dim2_size;

    // rotations[0..n1-1]
    vector<Ciphertext> slot_rotations = generate_rotations(slot_query, n1);

    vector<Ciphertext> row_results;
    row_results.resize(num_rows, Ciphertext(pool_));

    for (size_t row = 0; row < num_rows; ++row)
    {
        row_results[row] = process_single_row_slot(slot_rotations, row);
    }

    return row_results;
}

Ciphertext PIRServer::process_single_row_slot(const vector<Ciphertext> &slot_rotations, size_t row_idx)
{
    const size_t n1 = sq_params_.dim1_n1;
    const size_t n2 = sq_params_.dim1_n2;
    const size_t num_cols = sq_params_.dim1_size;

    const size_t base_idx = row_idx * num_cols;
    const size_t remaining = (base_idx < ntt_database_.size()) ? (ntt_database_.size() - base_idx) : 0;
    const size_t actual_cols = std::min(num_cols, remaining);

    return bsgs_inner_product_plain_ref(slot_rotations, base_idx, actual_cols, n1, n2);
}

// ============================================================================
// Step 2: Col Query (kept for compatibility)
// ============================================================================
Ciphertext PIRServer::process_col_query(const Ciphertext &col_query,
                                        const vector<Ciphertext> &row_results)
{
    const size_t n1 = sq_params_.dim2_n1;
    const size_t num_rows = row_results.size();
    const size_t n2_actual = (num_rows + n1 - 1) / n1;

    vector<Ciphertext> col_rotations = generate_rotations(col_query, n1);
    return bsgs_inner_product_cipher(col_rotations, row_results, n1, n2_actual);
}

// ============================================================================
// BSGS inner product: ct_rotations (NTT) ⋅ plaintexts (NTT)
// Optimized: reuse temp ciphertext, avoid copying ct for multiply_plain_inplace
// ============================================================================
Ciphertext PIRServer::bsgs_inner_product_plain_ref(const vector<Ciphertext> &ct_rotations,
                                                   size_t db_base_idx, size_t num_plaintexts,
                                                   size_t n1, size_t n2)
{
    if (num_plaintexts == 0) return Ciphertext(pool_);

    Ciphertext result(pool_);
    bool result_initialized = false;

    Ciphertext giant(pool_);
    Ciphertext temp(pool_);

    for (size_t j = 0; j < n2; ++j)
    {
        const size_t start_idx = j * n1;
        if (start_idx >= num_plaintexts) break;

        const size_t end_idx = std::min(start_idx + n1, num_plaintexts);
        const size_t chunk_sz = end_idx - start_idx;
        if (chunk_sz == 0) continue;

        bool giant_initialized = false;

        for (size_t i = 0; i < chunk_sz; ++i)
        {
            const Plaintext &pt = ntt_database_[db_base_idx + start_idx + i];

            auto t0 = chrono::high_resolution_clock::now();
            evaluator_->multiply_plain(ct_rotations[i], pt, temp); // out-of-place
            auto t1 = chrono::high_resolution_clock::now();

            slot_mult_time_ms_ += chrono::duration<double, milli>(t1 - t0).count();
            slot_mult_count_++;
            stat_plaintext_mults_++;

            if (!giant_initialized)
            {
                giant = temp;
                giant_initialized = true;
            }
            else
            {
                evaluator_->add_inplace(giant, temp);
            }
        }

        if (!giant_initialized) continue;

        // giant step rotation by j*n1
        if (j > 0)
        {
            auto t0 = chrono::high_resolution_clock::now();
            evaluator_->rotate_rows_inplace(giant, static_cast<int>(j * n1), galois_keys_);
            auto t1 = chrono::high_resolution_clock::now();

            slot_rotation_time_ms_ += chrono::duration<double, milli>(t1 - t0).count();
            slot_rotation_count_++;
            stat_rotations_++;
        }

        if (!result_initialized)
        {
            result = giant;
            result_initialized = true;
        }
        else
        {
            evaluator_->add_inplace(result, giant);
        }
    }

    return result;
}

// ============================================================================
// BSGS inner product: query_rotations ⋅ data_cts
// Optimized: reuse temp_product, no per-iteration Ciphertext allocation
// ============================================================================
Ciphertext PIRServer::bsgs_inner_product_cipher(const vector<Ciphertext> &query_rotations,
                                                const vector<Ciphertext> &data_cts,
                                                size_t n1, size_t n2)
{
    const size_t num_data = data_cts.size();

    Ciphertext result(pool_);
    bool result_initialized = false;

    Ciphertext giant(pool_);
    Ciphertext temp_product(pool_);

    for (size_t j = 0; j < n2; ++j)
    {
        const size_t base = j * n1;
        if (base >= num_data) break;

        bool giant_initialized = false;
        const size_t max_i = std::min(n1, num_data - base);

        for (size_t i = 0; i < max_i; ++i)
        {
            const size_t data_idx = base + i;
            stat_ciphertext_mults_++;

            if (!giant_initialized)
            {
                evaluator_->multiply(data_cts[data_idx], query_rotations[i], giant);
                giant_initialized = true;
            }
            else
            {
                evaluator_->multiply(data_cts[data_idx], query_rotations[i], temp_product);
                evaluator_->add_inplace(giant, temp_product);
            }
        }

        if (!giant_initialized) continue;

        evaluator_->relinearize_inplace(giant, relin_keys_);
        stat_relinearizations_++;

        if (j > 0)
        {
            evaluator_->rotate_rows_inplace(giant, static_cast<int>(j * n1), galois_keys_);
            stat_rotations_++;
        }

        if (!result_initialized)
        {
            result = giant;
            result_initialized = true;
        }
        else
        {
            evaluator_->add_inplace(result, giant);
        }
    }

    return result;
}

// ============================================================================
// Optimal BSGS params (unchanged)
// ============================================================================
BSGSParams PIRServer::calculate_optimal_bsgs_params(size_t dim_size, size_t plaintext_matrix_rows) const
{
    BSGSParams optimal_params;
    size_t min_cost = numeric_limits<size_t>::max();

    size_t max_n1 = static_cast<size_t>(sqrt(static_cast<double>(dim_size))) + 1;
    for (size_t n1 = 1; n1 <= max_n1; ++n1)
    {
        size_t n2 = (dim_size + n1 - 1) / n1;
        size_t cost = n1 + n2 * plaintext_matrix_rows;
        if (cost < min_cost)
        {
            min_cost = cost;
            optimal_params.n1 = n1;
            optimal_params.n2 = n2;
        }
    }

    while (optimal_params.n1 * optimal_params.n2 < dim_size) optimal_params.n2++;
    return optimal_params;
}

// ============================================================================// Batch Query 主处理方法// ============================================================================
BatchQueryResponse PIRServer::process_batch_queries(const BatchQueryResult &query)
{
    if (!context_ || !evaluator_) throw runtime_error("Server not initialized. Call init() first.");
    if (!keys_set_) throw runtime_error("Client keys not set. Call set_client_keys() first.");
    if (!database_set_) throw runtime_error("Database not set. Call set_database_batch_query() first.");
    if (!is_batch_mode_) throw runtime_error("Server is not in batch mode.");

    reset_stats();
    PIRLOG2("[PIRServer] process_batch_queries start");

    auto total_start = chrono::high_resolution_clock::now();

    BatchQueryResponse result;
    result.responses.reserve(query.col_queries.size());

    // 处理每个矩阵的查询
    for (size_t m = 0; m < query.col_queries.size(); ++m) {
        // Step 1: Slot Query 处理
        auto slot_start = chrono::high_resolution_clock::now();
        
        // 获取当前矩阵的槽选择查询
        const Ciphertext& slot_query = query.slot_selections[m];
        
        // 生成槽旋转
        vector<Ciphertext> slot_rotations = generate_rotations(slot_query, bp_params_.d2_n1);
        
        // 处理每一行
        vector<Ciphertext> row_results;
        row_results.resize(bp_params_.rows_per_plaintext, Ciphertext(pool_));
        
        for (size_t row = 0; row < bp_params_.rows_per_plaintext; ++row) {
            // 计算当前行在数据库中的起始索引
            size_t base_idx = m * bp_params_.rows_per_plaintext * bp_params_.d2 + row * bp_params_.d2;
            
            // 使用现有的bsgs_inner_product_plain_ref方法处理
            Ciphertext row_result = bsgs_inner_product_plain_ref(slot_rotations, base_idx, bp_params_.d2, bp_params_.d2_n1, bp_params_.d2_n2);
            row_results[row] = move(row_result);
        }
        
        auto slot_end = chrono::high_resolution_clock::now();
        result.slot_process_time_ms += chrono::duration<double, milli>(slot_end - slot_start).count();
        
        // Step 2: Col Query 处理
        auto col_start = chrono::high_resolution_clock::now();
        
        const Ciphertext& col_query = query.col_queries[m];
        
        // 生成列旋转
        vector<Ciphertext> col_rotations = generate_rotations(col_query, bp_params_.n1);
        
        // 执行BSGS内积
        Ciphertext response = bsgs_inner_product_cipher(col_rotations, row_results, bp_params_.n1, bp_params_.n2);
        
        auto col_end = chrono::high_resolution_clock::now();
        result.col_process_time_ms += chrono::duration<double, milli>(col_end - col_start).count();
        
        // 保存响应
        result.responses.push_back(move(response));
    }
    
    auto total_end = chrono::high_resolution_clock::now();
    result.total_time_ms = chrono::duration<double, milli>(total_end - total_start).count();
    
    // 填充统计信息
    result.num_plaintext_mults = stat_plaintext_mults_;
    result.num_ciphertext_mults = stat_ciphertext_mults_;
    result.num_rotations = stat_rotations_;
    result.num_relinearizations = stat_relinearizations_;
    
    result.slot_rotation_count = slot_rotation_count_;
    result.slot_mult_count = slot_mult_count_;
    
    result.rotation_time_ms = slot_rotation_time_ms_;
    result.mult_time_ms = slot_mult_time_ms_;
    
    PIRLOG2("[PIRServer] batch_queries done. total_ms=" << result.total_time_ms
            << ", pt_mult=" << stat_plaintext_mults_
            << ", ct_mult=" << stat_ciphertext_mults_
            << ", rot=" << stat_rotations_
            << ", relin=" << stat_relinearizations_);
    
    return result;
}

// ============================================================================// Batch Query 槽查询处理// ============================================================================
vector<Ciphertext> PIRServer::process_batch_slot_queries(const vector<Ciphertext>& slot_queries)
{
    vector<Ciphertext> results;
    results.reserve(slot_queries.size());
    
    for (const auto& slot_query : slot_queries) {
        // 生成槽旋转
        vector<Ciphertext> slot_rotations = generate_rotations(slot_query, bp_params_.d2_n1);
        
        // 处理每一行
        vector<Ciphertext> row_results;
        row_results.resize(bp_params_.rows_per_plaintext, Ciphertext(pool_));
        
        for (size_t row = 0; row < bp_params_.rows_per_plaintext; ++row) {
            // 计算当前行在数据库中的起始索引
            size_t base_idx = row * bp_params_.d2;
            
            // 使用现有的bsgs_inner_product_plain_ref方法处理
            Ciphertext row_result = bsgs_inner_product_plain_ref(slot_rotations, base_idx, bp_params_.d2, bp_params_.d2_n1, bp_params_.d2_n2);
            row_results[row] = move(row_result);
        }
        
        // 这里可以添加后续处理
        // 目前直接返回row_results
        results.push_back(move(row_results[0]));
    }
    
    return results;
}

// ============================================================================// Batch Query 列查询处理// ============================================================================
vector<Ciphertext> PIRServer::process_batch_col_queries(const vector<Ciphertext>& col_queries, const vector<Ciphertext>& slot_results)
{
    vector<Ciphertext> results;
    results.reserve(col_queries.size());
    
    for (size_t i = 0; i < col_queries.size(); ++i) {
        const Ciphertext& col_query = col_queries[i];
        
        // 生成列旋转
        vector<Ciphertext> col_rotations = generate_rotations(col_query, bp_params_.n1);
        
        // 执行BSGS内积
        Ciphertext response = bsgs_inner_product_cipher(col_rotations, slot_results, bp_params_.n1, bp_params_.n2);
        
        results.push_back(move(response));
    }
    
    return results;
}

// ============================================================================// Rotation steps required for Galois keys// ============================================================================
vector<int> PIRServer::get_required_rotation_steps() const
{
    vector<int> steps;
    if (!database_set_) return steps;

    if (is_batch_mode_) {
        // Batch 模式旋转步骤
        const size_t n1_slot = bp_params_.d2_n1;
        const size_t n2_slot = bp_params_.d2_n2;
        const size_t n1_col  = bp_params_.n1;
        const size_t n2_col  = bp_params_.n2;

        // baby steps
        for (size_t i = 1; i < n1_slot; ++i) steps.push_back(static_cast<int>(i));
        for (size_t i = 1; i < n1_col;  ++i) steps.push_back(static_cast<int>(i));

        // giant steps
        for (size_t j = 1; j < n2_slot; ++j) steps.push_back(static_cast<int>(j * n1_slot));
        for (size_t j = 1; j < n2_col;  ++j) steps.push_back(static_cast<int>(j * n1_col));
    } else {
        // Single 模式旋转步骤
        const size_t n1_slot = sq_params_.dim1_n1;
        const size_t n2_slot = sq_params_.dim1_n2;
        const size_t n1_col  = sq_params_.dim2_n1;
        const size_t n2_col  = sq_params_.dim2_n2;

        // baby steps
        for (size_t i = 1; i < n1_slot; ++i) steps.push_back(static_cast<int>(i));
        for (size_t i = 1; i < n1_col;  ++i) steps.push_back(static_cast<int>(i));

        // giant steps
        for (size_t j = 1; j < n2_slot; ++j) steps.push_back(static_cast<int>(j * n1_slot));
        for (size_t j = 1; j < n2_col;  ++j) steps.push_back(static_cast<int>(j * n1_col));
    }

    sort(steps.begin(), steps.end());
    steps.erase(unique(steps.begin(), steps.end()), steps.end());
    return steps;
}

// ============================================================================// print_status (not in hot path; keep verbose at level>=1)// ============================================================================
void PIRServer::print_status() const
{
    // This function is diagnostic; guard with PIRLOG1-style to keep bench clean.
#if PIR_SERVER_LOG_LEVEL >= 1
    cout << "\n╔════════════════════════════════════════════════════════════════╣" << endl;
    cout << "║                    PIRServer 状态                              ║" << endl;
    cout << "╠════════════════════════════════════════════════════════════════╣" << endl;
    cout << "║  初始化状态   : " << setw(45) << (context_ ? "已初始化" : "未初始化") << " ║" << endl;
    cout << "║  密钥状态     : " << setw(45) << (keys_set_ ? "已设置" : "未设置") << " ║" << endl;
    cout << "║  数据库状态   : " << setw(45) << (database_set_ ? "已设置" : "未设置") << " ║" << endl;
    cout << "║  模式         : " << setw(45) << (is_batch_mode_ ? "Batch Query" : "Single Query") << " ║" << endl;

    if (database_set_) {
        cout << "╠════════════════════════════════════════════════════════════════╣" << endl;
        cout << "║  数据库明文数 : " << setw(45) << ntt_database_.size() << " ║" << endl;
        
        if (is_batch_mode_) {
            cout << "║  Batch Size   : " << setw(45) << bp_params_.batch_size << " ║" << endl;
            cout << "║  Num Matrices : " << setw(45) << bp_params_.num_matrices << " ║" << endl;
            cout << "║  Buckets      : " << setw(45) << bp_params_.B << " ║" << endl;
            cout << "║  d1           : " << setw(45) << bp_params_.d1 << " ║" << endl;
            cout << "║  g            : " << setw(45) << bp_params_.g << " ║" << endl;
            cout << "║  d2           : " << setw(45) << bp_params_.d2 << " ║" << endl;
        } else {
            cout << "║  矩阵行数     : " << setw(45) << sq_params_.dim2_size << " ║" << endl;
            cout << "║  矩阵列数     : " << setw(45) << sq_params_.dim1_size << " ║" << endl;
        }
    }

    cout << "╚════════════════════════════════════════════════════════════════╝" << endl;
#endif
}
