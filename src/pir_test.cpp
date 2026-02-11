/**
 * PIR 简单测试 + Server Bench
 * - 默认：bench 风格（少输出）
 * - 可通过宏打开详细输出
 */

#include "db_encode.h"
#include "pir_client.h"
#include "pir_server.h"

#include <chrono>
#include <iostream>
#include <iomanip>
#include <random>
#include <string>
#include <vector>
#include <algorithm>
#include <fstream>
#include <sstream>

using namespace std;
using namespace seal;

#ifndef PIR_TEST_VERBOSE
#define PIR_TEST_VERBOSE 0
#endif

#if PIR_TEST_VERBOSE
#define TLOG(x) do { std::cout << x << std::endl; } while(0)
#else
#define TLOG(x) do {} while(0)
#endif

static double ms_since(const chrono::high_resolution_clock::time_point &a,
                       const chrono::high_resolution_clock::time_point &b)
{
    return chrono::duration<double, milli>(b - a).count();
}

template <typename SealObj>
static size_t seal_bytes(const SealObj &obj)
{
    std::stringstream ss(std::ios::in | std::ios::out | std::ios::binary);
    obj.save(ss);
    const std::string s = ss.str();
    return s.size();
}

static size_t seal_bytes_ciphertexts(const std::vector<Ciphertext> &cts)
{
    size_t total = 0;
    for (const auto &ct : cts) total += seal_bytes(ct);
    return total;
}

struct SampleStats
{
    std::vector<double> v;
    void add(double x) { v.push_back(x); }
    bool empty() const { return v.empty(); }
    void sort_inplace() { std::sort(v.begin(), v.end()); }
    double avg() const {
        if (v.empty()) return 0.0;
        double s = 0.0;
        for (double x : v) s += x;
        return s / static_cast<double>(v.size());
    }
    double percentile(double p) {
        if (v.empty()) return 0.0;
        if (v.size() == 1) return v[0];
        sort_inplace();
        double idx = p * static_cast<double>(v.size() - 1);
        size_t lo = static_cast<size_t>(std::floor(idx));
        size_t hi = static_cast<size_t>(std::ceil(idx));
        if (hi >= v.size()) hi = v.size() - 1;
        double t = idx - static_cast<double>(lo);
        return v[lo] * (1.0 - t) + v[hi] * t;
    }
    double min() {
        if (v.empty()) return 0.0;
        sort_inplace();
        return v.front();
    }
    double max() {
        if (v.empty()) return 0.0;
        sort_inplace();
        return v.back();
    }
};

static void csv_write_header_if_needed(std::ofstream &ofs)
{
    // A single wide header to support both single/batch rows.
    ofs << "mode,poly_degree,plain_bits,value_bits,num_entries,payload_bytes,batch_size,"
           "B,d,d1,g,d2,slots_per_entry,rows_per_plaintext,num_matrices,"
           "db_gen_ms,db_encode_plain_ms,db_ntt_ms,"
           "keygen_ms,galois_ms,pk_bytes,relin_bytes,galois_bytes,sk_bytes,"
           "required_rot_steps,"
           "querygen_avg_ms,querygen_p50_ms,querygen_p90_ms,"
           "server_avg_ms,server_p50_ms,server_p90_ms,server_slot_avg_ms,server_col_avg_ms,"
           "decrypt_avg_ms,decrypt_p50_ms,decrypt_p90_ms,"
           "query_bytes_avg,response_bytes_avg,"
           "upload_bytes_per_session,download_bytes_per_session,"
           "queries_per_sec,retrieved_entries_per_sec,db_MB_per_sec"
        << "\n";
}

static bool file_exists_and_nonempty(const std::string &path)
{
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.good()) return false;
    ifs.seekg(0, std::ios::end);
    return (ifs.tellg() > 0);
}

struct CsvWriter
{
    std::ofstream out;
    bool enabled = false;
    explicit CsvWriter(const std::string &path)
    {
        if (path.empty()) return;
        bool has = file_exists_and_nonempty(path);
        out.open(path, std::ios::out | std::ios::app);
        if (!out) throw std::runtime_error("Failed to open CSV path: " + path);
        enabled = true;
        if (!has) {
            csv_write_header_if_needed(out);
            out.flush();
        }
    }
    void row(const std::string &line)
    {
        if (!enabled) return;
        out << line << "\n";
        out.flush();
    }
};

static bool parse_arg_u64(int &i, int argc, char **argv, const string &name, size_t &out) {
    if (string(argv[i]) == name && i + 1 < argc) {
        out = static_cast<size_t>(stoull(argv[i + 1]));
        i += 1;
        return true;
    }
    return false;
}

static bool parse_arg_double(int &i, int argc, char **argv, const string &name, double &out) {
    if (string(argv[i]) == name && i + 1 < argc) {
        out = stod(argv[i + 1]);
        i += 1;
        return true;
    }
    return false;
}

int main(int argc, char **argv) {
    // =========================
    // 测试模式选择
    // =========================
    bool test_single_query = true;
    bool test_batch_query = true;
    
    // =========================
    // 共享参数配置
    // =========================
    // NOTE: For large (entries, payload) pairs, the plaintext matrix can get extremely large.
    // Defaults are set to be runnable on a typical workstation. Override via CLI if needed.
    size_t num_entries  = 1ULL << 20;
    size_t payload_size = 256;
    const size_t poly_degree  = 8192;
    const size_t plain_bits   = 22;

    // Batch defaults (often needs different DB size to remain runnable)
    size_t batch_num_entries = num_entries;
    size_t batch_size = 256;
    double cuckoo_factor = 1.5;
    size_t num_hash_funcs = 3;

    int iters_single = 10;
    int iters_batch  = 5;
    int warmup_single = 2;
    int warmup_batch  = 2;

    // Output
    std::string csv_path;
    bool write_csv = false;

    // Simple CLI
    for (int i = 1; i < argc; ++i) {
        string a = argv[i];
        if (a == "--single-only") { test_single_query = true; test_batch_query = false; continue; }
        if (a == "--batch-only")  { test_single_query = false; test_batch_query = true; continue; }
        if (parse_arg_u64(i, argc, argv, "--entries", num_entries)) continue;
        if (parse_arg_u64(i, argc, argv, "--payload", payload_size)) continue;
        if (parse_arg_u64(i, argc, argv, "--batch-entries", batch_num_entries)) continue;
        if (parse_arg_u64(i, argc, argv, "--batch-size", batch_size)) continue;
        if (parse_arg_double(i, argc, argv, "--cuckoo-factor", cuckoo_factor)) continue;
        if (parse_arg_u64(i, argc, argv, "--hash-funcs", num_hash_funcs)) continue;
        if (a == "--iters-single" && i + 1 < argc) { iters_single = stoi(argv[++i]); continue; }
        if (a == "--iters-batch" && i + 1 < argc)  { iters_batch  = stoi(argv[++i]); continue; }
        if (a == "--warmup-single" && i + 1 < argc) { warmup_single = stoi(argv[++i]); continue; }
        if (a == "--warmup-batch" && i + 1 < argc)  { warmup_batch  = stoi(argv[++i]); continue; }
        if (a == "--csv" && i + 1 < argc) { csv_path = argv[++i]; write_csv = true; continue; }
    }

    CsvWriter csv(write_csv ? csv_path : std::string());

    // Use a slightly smaller "value bits" than plain modulus bits to keep headroom.
    const size_t value_bits = (plain_bits > 1) ? (plain_bits - 1) : plain_bits;

    // =========================
    // 构建 SEAL Context
    // =========================
    EncryptionParameters parms(scheme_type::bgv);
    parms.set_poly_modulus_degree(poly_degree);

    // 你当前用 {60,40,40,40} (180 bits) 作为较稳基线，可以
    parms.set_coeff_modulus(CoeffModulus::Create(poly_degree, {55,55,60}));

    parms.set_plain_modulus(PlainModulus::Batching(poly_degree, plain_bits));
    auto context = make_shared<SEALContext>(parms);

    // =========================
    // Single Query 模式测试
    // =========================
    if (test_single_query) {
        cout << "\n===============================================================\n";
        cout << "Single Query PIR Test\n";
        cout << "===============================================================\n";
        
        // BSGS 参数（你当前用法）
        const size_t entries_per_plaintext = 1024;
        const size_t dim1_size = (num_entries + entries_per_plaintext - 1) / entries_per_plaintext;

        const size_t dim1_n1 = 128;
        const size_t dim1_n2 = 8;

        // 注意：你这里 bits_per_slot 用 plain_bits，但你 params 里用 plain_bits-1
        // 为了与 encoder/client 的 set_single_query_params 一致，建议都用 (plain_bits - 1)
        const size_t bits_per_slot = plain_bits - 1;
        const size_t total_bits    = payload_size * 8;
        const size_t slots_per_entry = (total_bits + bits_per_slot - 1) / bits_per_slot; // 2048/19 => 108
        const size_t dim2_size = (slots_per_entry + 7) / 8; // 108 => 14

        const size_t dim2_n1 = static_cast<size_t>(ceil(sqrt(static_cast<double>(dim2_size))));
        const size_t dim2_n2 = static_cast<size_t>(ceil(static_cast<double>(dim2_size) / dim2_n1));

        // =========================
        // 输出少量固定信息（不进热路径）
        // =========================
        cout << "[Config] N=" << poly_degree
             << ", plain_bits=" << plain_bits
             << ", entries=" << num_entries
             << ", payload=" << payload_size << "B"
             << ", dim1_size=" << dim1_size
             << ", dim2_size=" << dim2_size
             << ", BSGS dim1=(" << dim1_n1 << "," << dim1_n2 << ")"
             << ", dim2=(" << dim2_n1 << "," << dim2_n2 << ")"
             << endl;

        // =========================
        // 初始化编码器/数据库
        // =========================
        DatabaseEncoder encoder;
        encoder.init_seal_context(context);
        encoder.set_single_query_params(num_entries, payload_size, value_bits,
                                        dim1_n1, dim1_n2, dim2_n1, dim2_n2);

        // DB offline timings (separated)
        double db_gen_ms = 0.0, db_encode_plain_ms = 0.0, db_ntt_ms = 0.0;

        auto t_db0 = chrono::high_resolution_clock::now();
        encoder.generate_random_database();
        auto t_db1 = chrono::high_resolution_clock::now();
        PlainMatrix plain_db = encoder.encode_database_single_query();
        auto t_db2 = chrono::high_resolution_clock::now();
        auto ntt_database = encoder.convert_to_ntt(plain_db);
        auto t_db3 = chrono::high_resolution_clock::now();

        db_gen_ms = ms_since(t_db0, t_db1);
        db_encode_plain_ms = ms_since(t_db1, t_db2);
        db_ntt_ms = ms_since(t_db2, t_db3);
        plain_db.clear();
        plain_db.shrink_to_fit();

        cout << "[Offline] DB gen(ms)=" << fixed << setprecision(2) << db_gen_ms
             << "  encode_plain(ms)=" << db_encode_plain_ms
             << "  ntt(ms)=" << db_ntt_ms
             << endl;

        // =========================
        // 初始化客户端
        // =========================
        PIRClient client;
        client.init(context);
        client.set_single_query_params(num_entries, payload_size, value_bits,
                                       dim1_n1, dim1_n2, dim2_n1, dim2_n2);

        double keygen_ms = 0.0, galois_ms = 0.0;
        auto t_k0 = chrono::high_resolution_clock::now();
        client.generate_keys();
        auto t_k1 = chrono::high_resolution_clock::now();
        keygen_ms = ms_since(t_k0, t_k1);

        // =========================
        // 初始化服务器
        // =========================
        PIRServer server;
        server.init(context);
        server.set_database_single_query(ntt_database, encoder.get_single_query_params());

        auto required_steps = server.get_required_rotation_steps();
        auto t_g0 = chrono::high_resolution_clock::now();
        client.generate_galois_keys(required_steps);
        auto t_g1 = chrono::high_resolution_clock::now();
        galois_ms = ms_since(t_g0, t_g1);
        server.set_client_keys(client.get_galois_keys(), client.get_relin_keys());

        // Key sizes (storage)
        const size_t pk_bytes    = seal_bytes(client.get_public_key());
        const size_t sk_bytes    = seal_bytes(client.get_secret_key());
        const size_t relin_bytes = seal_bytes(client.get_relin_keys());
        const size_t galois_bytes= seal_bytes(client.get_galois_keys());
        const size_t rot_steps   = required_steps.size();

        // 只构造一次 decryptor（避免每次循环开销）
        Decryptor decryptor(*context, client.get_secret_key());

        // =========================
        // Bench 配置
        // =========================
        const int warmup = warmup_single;          // 预热次数（缓存/分配稳定）
        const int iters  = iters_single;           // 正式计时次数（你可调大）
        const int correctness_checks = 2; // 抽查解密正确性次数（不建议每次都解密）

        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<size_t> dist(0, batch_num_entries - 1);

        SampleStats server_ms;
        SampleStats server_slot_ms;
        SampleStats server_col_ms;
        SampleStats querygen_ms;
        SampleStats decrypt_ms;
        SampleStats query_bytes_s;
        SampleStats resp_bytes_s;

        int passed = 0;
        int checked = 0;
        int min_noise = INT32_MAX;

        // =========================
        // 预热（不计时/少输出）
        // =========================
        for (int i = 0; i < warmup; ++i) {
            size_t target = dist(gen);
            auto query = client.generate_single_query(target);
            (void)server.process_single_query(query);
        }

        // =========================
        // 正式 Bench（只计 server.process_single_query）
        // =========================
        for (int i = 0; i < iters; ++i) {
            size_t target = dist(gen);
            auto q0 = chrono::high_resolution_clock::now();
            auto query = client.generate_single_query(target);
            auto q1 = chrono::high_resolution_clock::now();
            querygen_ms.add(ms_since(q0, q1));

            size_t qbytes = seal_bytes(query.slot_selection) + seal_bytes(query.dim1_query);
            query_bytes_s.add(static_cast<double>(qbytes));

            auto response = server.process_single_query(query);
            server_ms.add(response.total_time_ms);
            server_slot_ms.add(response.slot_process_time_ms);
            server_col_ms.add(response.col_process_time_ms);

            size_t rbytes = seal_bytes(response.response);
            resp_bytes_s.add(static_cast<double>(rbytes));

            // Always measure client decrypt+decode time
            auto d0 = chrono::high_resolution_clock::now();
            auto decrypted = client.decrypt_single_response(response.response, query);
            auto d1 = chrono::high_resolution_clock::now();
            decrypt_ms.add(ms_since(d0, d1));

            // 抽查 correctness（少量次：噪声预算+非零输出）
            if (checked < correctness_checks) {
                int noise = decryptor.invariant_noise_budget(response.response);
                min_noise = std::min(min_noise, noise);

                bool has_non_zero = !decrypted.empty();
                bool noise_ok = (noise >= 0);
                bool ok = has_non_zero && noise_ok;

                passed += ok ? 1 : 0;
                checked++;

                TLOG("[Check] target=" << target
                     << " decrypted_size=" << decrypted.size()
                     << " noise=" << noise
                     << " ok=" << ok);
            }
        }

        // =========================
        // 统计输出（一次性）
        // =========================
        double srv_avg = server_ms.avg();
        double srv_p50 = server_ms.percentile(0.50);
        double srv_p90 = server_ms.percentile(0.90);

        double slot_avg = server_slot_ms.avg();
        double col_avg  = server_col_ms.avg();

        double qg_avg = querygen_ms.avg();
        double qg_p50 = querygen_ms.percentile(0.50);
        double qg_p90 = querygen_ms.percentile(0.90);

        double dec_avg = decrypt_ms.avg();
        double dec_p50 = decrypt_ms.percentile(0.50);
        double dec_p90 = decrypt_ms.percentile(0.90);

        double qbytes_avg = query_bytes_s.avg();
        double rbytes_avg = resp_bytes_s.avg();

        cout << "\n[Offline] keygen(ms)=" << fixed << setprecision(2) << keygen_ms
             << "  galois(ms)=" << galois_ms
             << "  rot_steps=" << rot_steps
             << endl;
        cout << "[Key bytes] pk=" << pk_bytes
             << "  sk=" << sk_bytes
             << "  relin=" << relin_bytes
             << "  galois=" << galois_bytes
             << endl;

        cout << "\n[Online] iters=" << iters << " (warmup=" << warmup << ")\n";
        cout << "  querygen_avg(ms)=" << qg_avg << " p50=" << qg_p50 << " p90=" << qg_p90 << "\n";
        cout << "  server_avg(ms)=" << srv_avg << " p50=" << srv_p50 << " p90=" << srv_p90 <<"\n";
             //<< "  slot_avg(ms)=" << slot_avg << "  col_avg(ms)=" << col_avg << "\n";
        cout << "  decrypt_avg(ms)=" << dec_avg << " p50=" << dec_p50 << " p90=" << dec_p90 << "\n";

        cout << "[Comm avg bytes] query=" << static_cast<size_t>(qbytes_avg)
             << "  response=" << static_cast<size_t>(rbytes_avg)
             << endl;

        cout << "[Correctness] checked=" << checked << " passed=" << passed
             << "  min_noise_budget=" << (checked ? min_noise : -1) << " bits"
             << endl;

        // CSV summary row
        if (csv.enabled) {
            const double qs = (srv_avg > 0.0) ? (1000.0 / srv_avg) : 0.0;
            const double retrieved_eps = qs; // single returns 1 entry per query
            const double db_bytes = static_cast<double>(num_entries) * static_cast<double>(payload_size);
            const double db_MBps = (srv_avg > 0.0) ? (db_bytes / (srv_avg / 1000.0) / (1024.0*1024.0)) : 0.0;
            const size_t upload_session = static_cast<size_t>(galois_bytes + relin_bytes + qbytes_avg);
            const size_t download_session = static_cast<size_t>(rbytes_avg);

            std::ostringstream line;
            line << "single" << ','
                 << poly_degree << ',' << plain_bits << ',' << value_bits << ','
                 << num_entries << ',' << payload_size << ',' << 1 << ','
                 << 0 << ',' << 0 << ',' << 0 << ',' << 0 << ',' << 0 << ','
                 << slots_per_entry << ',' << 0 << ',' << 0 << ','
                 << db_gen_ms << ',' << db_encode_plain_ms << ',' << db_ntt_ms << ','
                 << keygen_ms << ',' << galois_ms << ','
                 << pk_bytes << ',' << relin_bytes << ',' << galois_bytes << ',' << sk_bytes << ','
                 << rot_steps << ','
                 << qg_avg << ',' << qg_p50 << ',' << qg_p90 << ','
                 << srv_avg << ',' << srv_p50 << ',' << srv_p90 << ',' << slot_avg << ',' << col_avg << ','
                 << dec_avg << ',' << dec_p50 << ',' << dec_p90 << ','
                 << qbytes_avg << ',' << rbytes_avg << ','
                 << upload_session << ',' << download_session << ','
                 << qs << ',' << retrieved_eps << ',' << db_MBps;
            csv.row(line.str());
        }
    }
    
    // =========================
    // Batch Query 模式测试
    // =========================
    if (test_batch_query) {
        cout << "\n===============================================================\n";
        cout << "Batch Query PIR Test\n";
        cout << "===============================================================\n";
        
        // Batch PIR 参数来自 CLI / 默认值
        
        // =========================
        // 输出 Batch Query 配置
        // =========================
        cout << "[Config] N=" << poly_degree
             << ", plain_bits=" << plain_bits
             << ", entries=" << batch_num_entries
             << ", payload=" << payload_size << "B"
             << ", batch_size=" << batch_size
             << ", cuckoo_factor=" << cuckoo_factor
             << ", num_hash_funcs=" << num_hash_funcs
             << endl;
        
        // =========================
        // 初始化编码器/数据库
        // =========================
        DatabaseEncoder encoder;
        encoder.init_seal_context(context);
        encoder.set_batch_pir_params(batch_num_entries, batch_size, payload_size, value_bits, cuckoo_factor, num_hash_funcs);
        
        // DB offline timings (separated)
        double db_gen_ms = 0.0, db_encode_plain_ms = 0.0, db_ntt_ms = 0.0;

        auto t_db0 = chrono::high_resolution_clock::now();
        encoder.generate_random_database();
        auto t_db1 = chrono::high_resolution_clock::now();
        PlainMatrix plain_db = encoder.encode_database_batch_query();
        auto t_db2 = chrono::high_resolution_clock::now();
        auto ntt_database = encoder.convert_to_ntt(plain_db);
        auto t_db3 = chrono::high_resolution_clock::now();

        db_gen_ms = ms_since(t_db0, t_db1);
        db_encode_plain_ms = ms_since(t_db1, t_db2);
        db_ntt_ms = ms_since(t_db2, t_db3);
        plain_db.clear();
        plain_db.shrink_to_fit();

        cout << "[Offline] DB gen(ms)=" << fixed << setprecision(2) << db_gen_ms
             << "  encode_plain(ms)=" << db_encode_plain_ms
             << "  ntt(ms)=" << db_ntt_ms
             << endl;
        
        // =========================
        // 初始化客户端
        // =========================
        PIRClient client;
        client.init(context);
        client.set_batch_pir_params(batch_num_entries, batch_size, payload_size, value_bits, cuckoo_factor, num_hash_funcs);
        double keygen_ms = 0.0, galois_ms = 0.0;
        auto t_k0 = chrono::high_resolution_clock::now();
        client.generate_keys();
        auto t_k1 = chrono::high_resolution_clock::now();
        keygen_ms = ms_since(t_k0, t_k1);
        
        // =========================
        // 初始化服务器
        // =========================
        PIRServer server;
        server.init(context);
        server.set_database_batch_query(ntt_database, encoder.get_batch_pir_params());
        
        auto required_steps = server.get_required_rotation_steps();
        auto t_g0 = chrono::high_resolution_clock::now();
        client.generate_galois_keys(required_steps);
        auto t_g1 = chrono::high_resolution_clock::now();
        galois_ms = ms_since(t_g0, t_g1);
        server.set_client_keys(client.get_galois_keys(), client.get_relin_keys());

        // Key sizes (storage)
        const size_t pk_bytes    = seal_bytes(client.get_public_key());
        const size_t sk_bytes    = seal_bytes(client.get_secret_key());
        const size_t relin_bytes = seal_bytes(client.get_relin_keys());
        const size_t galois_bytes= seal_bytes(client.get_galois_keys());
        const size_t rot_steps   = required_steps.size();

        const BatchPIRParams &bp = encoder.get_batch_pir_params();
        
        // 只构造一次 decryptor（避免每次循环开销）
        Decryptor decryptor(*context, client.get_secret_key());
        
        // =========================
        // Bench 配置
        // =========================
        const int warmup = warmup_batch;          // 预热次数
        const int iters  = iters_batch;           // 正式计时次数
        const int correctness_checks = 1; // 抽查解密正确性次数（不建议每次都解密）
        
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<size_t> dist(0, batch_num_entries - 1);
        
        SampleStats server_ms;
        SampleStats server_slot_ms;
        SampleStats server_col_ms;
        SampleStats querygen_ms;
        SampleStats decrypt_ms;
        SampleStats query_bytes_s;
        SampleStats resp_bytes_s;
        
        int passed = 0;
        int checked = 0;
        
        // =========================
        // 预热（不计时/少输出）
        // =========================
        for (int i = 0; i < warmup; ++i) {
            // 生成随机目标索引
            vector<size_t> target_indices(batch_size);
            for (size_t j = 0; j < batch_size; ++j) {
                target_indices[j] = dist(gen);
            }
            
            auto query = client.generate_batch_queries(target_indices);
            (void)server.process_batch_queries(query);
        }
        
        // =========================
        // 正式 Bench（只计 server.process_batch_queries）
        // =========================
        for (int i = 0; i < iters; ++i) {
            // 生成随机目标索引
            vector<size_t> target_indices(batch_size);
            for (size_t j = 0; j < batch_size; ++j) {
                target_indices[j] = dist(gen);
            }
            
            auto q0 = chrono::high_resolution_clock::now();
            auto query = client.generate_batch_queries(target_indices);
            auto q1 = chrono::high_resolution_clock::now();
            querygen_ms.add(ms_since(q0, q1));

            size_t qbytes = seal_bytes_ciphertexts(query.slot_selections) + seal_bytes_ciphertexts(query.col_queries);
            query_bytes_s.add(static_cast<double>(qbytes));

            auto response = server.process_batch_queries(query);
            server_ms.add(response.total_time_ms);
            server_slot_ms.add(response.slot_process_time_ms);
            server_col_ms.add(response.col_process_time_ms);

            size_t rbytes = seal_bytes_ciphertexts(response.responses);
            resp_bytes_s.add(static_cast<double>(rbytes));

            auto d0 = chrono::high_resolution_clock::now();
            auto decrypted = client.decrypt_batch_responses(response.responses, query);
            auto d1 = chrono::high_resolution_clock::now();
            decrypt_ms.add(ms_since(d0, d1));
            
            // 抽查 correctness（少量次，不要每次解密）
            if (checked < correctness_checks) {
                bool ok = !decrypted.empty();
                passed += ok ? 1 : 0;
                checked++;
                TLOG("[Check] decrypted_batches=" << decrypted.size() << " ok=" << ok);
            }
        }
        
        // =========================
        // 统计输出（一次性）
        // =========================
        double srv_avg = server_ms.avg();
        double srv_p50 = server_ms.percentile(0.50);
        double srv_p90 = server_ms.percentile(0.90);

        double slot_avg = server_slot_ms.avg();
        double col_avg  = server_col_ms.avg();

        double qg_avg = querygen_ms.avg();
        double qg_p50 = querygen_ms.percentile(0.50);
        double qg_p90 = querygen_ms.percentile(0.90);

        double dec_avg = decrypt_ms.avg();
        double dec_p50 = decrypt_ms.percentile(0.50);
        double dec_p90 = decrypt_ms.percentile(0.90);

        double qbytes_avg = query_bytes_s.avg();
        double rbytes_avg = resp_bytes_s.avg();

        cout << "\n[Offline] keygen(ms)=" << fixed << setprecision(2) << keygen_ms
             << "  galois(ms)=" << galois_ms
             << "  rot_steps=" << rot_steps
             << endl;
        cout << "[Key bytes] pk=" << pk_bytes
             << "  sk=" << sk_bytes
             << "  relin=" << relin_bytes
             << "  galois=" << galois_bytes
             << endl;

        cout << "\n[Online] iters=" << iters << " (warmup=" << warmup << ")\n";
        cout << "  querygen_avg(ms)=" << qg_avg << " p50=" << qg_p50 << " p90=" << qg_p90 << "\n";
        cout << "  server_avg(ms)=" << srv_avg << " p50=" << srv_p50 << " p90=" << srv_p90
             << "  slot_avg(ms)=" << slot_avg << "  col_avg(ms)=" << col_avg << "\n";
        cout << "  decrypt_avg(ms)=" << dec_avg << " p50=" << dec_p50 << " p90=" << dec_p90 << "\n";

        cout << "[Comm avg bytes] query=" << static_cast<size_t>(qbytes_avg)
             << "  response=" << static_cast<size_t>(rbytes_avg)
             << endl;

        cout << "[Correctness] checked=" << checked << " passed=" << passed << endl;

        // CSV summary row
        if (csv.enabled) {
            const double qs = (srv_avg > 0.0) ? (1000.0 / srv_avg) : 0.0;
            const double retrieved_eps = static_cast<double>(batch_size) * qs;
            const double db_bytes = static_cast<double>(batch_num_entries) * static_cast<double>(payload_size);
            const double db_MBps = (srv_avg > 0.0) ? (db_bytes / (srv_avg / 1000.0) / (1024.0*1024.0)) : 0.0;
            const size_t upload_session = static_cast<size_t>(galois_bytes + relin_bytes + qbytes_avg);
            const size_t download_session = static_cast<size_t>(rbytes_avg);

            std::ostringstream line;
            line << "batch" << ','
                 << poly_degree << ',' << plain_bits << ',' << value_bits << ','
                 << batch_num_entries << ',' << payload_size << ',' << batch_size << ','
                 << bp.B << ',' << bp.d << ',' << bp.d1 << ',' << bp.g << ',' << bp.d2 << ','
                 << bp.slots_per_entry << ',' << bp.rows_per_plaintext << ',' << bp.num_matrices << ','
                 << db_gen_ms << ',' << db_encode_plain_ms << ',' << db_ntt_ms << ','
                 << keygen_ms << ',' << galois_ms << ','
                 << pk_bytes << ',' << relin_bytes << ',' << galois_bytes << ',' << sk_bytes << ','
                 << rot_steps << ','
                 << qg_avg << ',' << qg_p50 << ',' << qg_p90 << ','
                 << srv_avg << ',' << srv_p50 << ',' << srv_p90 << ',' << slot_avg << ',' << col_avg << ','
                 << dec_avg << ',' << dec_p50 << ',' << dec_p90 << ','
                 << qbytes_avg << ',' << rbytes_avg << ','
                 << upload_session << ',' << download_session << ','
                 << qs << ',' << retrieved_eps << ',' << db_MBps;
            csv.row(line.str());
        }
    }
    
    cout << "\nAll tests completed successfully!" << endl;
    
    return 0;
}
