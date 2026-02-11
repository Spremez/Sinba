/**
 * SEAL Bench 对比测试
 *
 * 用于与SEAL原生bench对比性能，验证优化效果
 * + 新增：
 *   4) ModSwitchToNextInplace 性能
 *   5) 噪声预算 & 连续 ModSwitch 噪声变化
 *   6) PIR-like 噪声 trace（按 rotate->mul_plain->add... + modswitch + mul_ct...）
 *
 * 兼容 SEAL 4.1.x：
 * - Plaintext NTT 转换：Evaluator::transform_to_ntt_inplace(Plaintext&, parms_id_type)
 * - Ciphertext NTT 转换：Evaluator::transform_to_ntt_inplace(Ciphertext&)
 * - 避免重复 NTT 转换（否则会抛: "encrypted is already in NTT form"）
 */

#include "db_encode.h"
#include "pir_client.h"
#include "pir_server.h"

#include <seal/seal.h>

#include <iostream>
#include <iomanip>
#include <random>
#include <chrono>
#include <vector>
#include <string>
#include <functional>
#include <algorithm>
#include <limits>

using namespace std;
using namespace seal;
using namespace chrono;

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------
static void print_coeff_chain(const SEALContext &context)
{
    cout << "\n[CoeffModulus chain]\n";
    size_t level = 0;
    for (auto cd = context.first_context_data(); cd; cd = cd->next_context_data(), ++level)
    {
        auto &cm = cd->parms().coeff_modulus();
        cout << "  level " << level << " (chain_index=" << cd->chain_index() << "): primes bits = [ ";
        size_t sum_bits = 0;
        for (auto &p : cm) { cout << p.bit_count() << " "; sum_bits += p.bit_count(); }
        cout << "], count=" << cm.size() << ", sum_bits≈" << sum_bits << "\n";
    }
}

// 打印 KSwitchKeys/RelinKeys/GaloisKeys 的 decomposition 情况
template <typename KSK>
static void print_kswitch_decomp(const string &name, const KSK &ksk)
{
    const auto &outer = ksk.data(); // vector<vector<PublicKey>>
    cout << "\n[" << name << " internal structure]\n";
    cout << "  outer(keys) = " << outer.size() << "\n";

    size_t min_inner = numeric_limits<size_t>::max();
    size_t max_inner = 0;

    for (size_t i = 0; i < outer.size(); ++i)
    {
        const auto &inner = outer[i];
        min_inner = min(min_inner, inner.size());
        max_inner = max(max_inner, inner.size());

        cout << "  key[" << i << "]: decomp_parts(inner size) = " << inner.size();

        // 每个分量是一个 PublicKey；它内部是一个 Ciphertext
        // 通常 pk.data().size() == 2（对应两项多项式）
        if (!inner.empty())
        {
            cout << "  | first part pk.data().size()=" << inner[0].data().size();

            // 也可以看 parms_id 是否一致（通常一致）
            // cout << "  | parms_id match? " << (inner[0].parms_id() == inner.back().parms_id());
        }
        cout << "\n";
    }

    if (!outer.empty())
    {
        cout << "  decomp_parts range: [" << min_inner << ", " << max_inner << "]\n";
        cout << "  (Interpretation) inner size 通常 ≈ 用于 key-switch 的 RNS 分解块数（与 coeff primes 数量强相关）\n";
    }
}

static void print_budget(const std::string &tag,
                         const SEALContext &context,
                         Decryptor &decryptor,
                         const Ciphertext &ct)
{
    int nb = decryptor.invariant_noise_budget(ct);
    auto data = context.get_context_data(ct.parms_id());
    size_t chain_idx = data ? data->chain_index() : 999999;

    cout << "   [" << tag << "] "
         << "noise_budget=" << nb << " bits"
         << ", size=" << ct.size()
         << ", chain_index=" << chain_idx
         << ", ntt=" << (ct.is_ntt_form() ? "yes" : "no")
         << endl;
}

static double time_us(std::function<void()> fn, int iters)
{
    fn(); // warmup
    double total = 0.0;
    for (int i = 0; i < iters; ++i)
    {
        auto t0 = high_resolution_clock::now();
        fn();
        auto t1 = high_resolution_clock::now();
        total += duration<double, micro>(t1 - t0).count();
    }
    return total / iters;
}

static size_t count_modswitch_levels(const SEALContext &context)
{
    size_t levels = 0;
    for (auto data = context.first_context_data(); data; data = data->next_context_data())
        ++levels;
    return levels;
}

static void print_chain_summary(const SEALContext &context)
{
    cout << "\n[CoeffModulus 链信息]" << endl;

    size_t lvl = 0;
    for (auto data = context.first_context_data(); data; data = data->next_context_data(), ++lvl)
    {
        auto &parms = data->parms();
        auto &cm = parms.coeff_modulus();
        size_t sum_bits = 0;

        cout << "  level " << lvl << ": primes bit_count = [ ";
        for (auto &p : cm)
        {
            cout << p.bit_count() << " ";
            sum_bits += p.bit_count();
        }
        cout << "], sum_bits≈" << sum_bits << endl;
    }

    size_t levels = count_modswitch_levels(context);
    cout << "  总 levels = " << levels << endl;
    cout << "  理论最大 mod_switch_to_next 次数 = " << (levels > 0 ? levels - 1 : 0) << endl;
}

static Plaintext make_random_plain_bgv(const SEALContext &context,
                                       size_t slot_count,
                                       uint64_t plain_modulus_value,
                                       std::mt19937_64 &gen,
                                       const MemoryPoolHandle &pool)
{
    BatchEncoder enc(context);
    vector<uint64_t> v(slot_count);
    std::uniform_int_distribution<uint64_t> dist(0, plain_modulus_value - 1);
    for (size_t i = 0; i < slot_count; ++i)
        v[i] = dist(gen);

    Plaintext pt(pool);
    enc.encode(v, pt);
    pt.parms_id() = seal::parms_id_zero; // batching 明文一般是 parms_id_zero
    return pt;
}

// 将 ciphertext 向下 modswitch 若干次，直到与 target_parms_id 相同（或到底）
static void align_cipher_to_parms_id_inplace(Evaluator &evaluator,
                                             const SEALContext &context,
                                             Ciphertext &ct,
                                             const parms_id_type &target_parms_id)
{
    if (ct.parms_id() == target_parms_id)
        return;

    for (;;)
    {
        auto data = context.get_context_data(ct.parms_id());
        if (!data)
            break;

        if (ct.parms_id() == target_parms_id)
            return;

        auto next = data->next_context_data();
        if (!next)
            break;

        evaluator.mod_switch_to_next_inplace(ct);

        if (ct.parms_id() == target_parms_id)
            return;
    }
}

// 避免重复 NTT 转换（SEAL 4.1.x：重复会 throw）
static inline void ensure_ct_ntt_inplace(Evaluator &evaluator, Ciphertext &ct)
{
    if (!ct.is_ntt_form())
    {
        evaluator.transform_to_ntt_inplace(ct);
    }
}

// BGV: pt 的 NTT 形态通常用 pt.parms_id()==target_parms_id 表示
// 若 pt 在非 zero 且非 target 的 parms_id：这里采取“严格策略”：直接 throw（避免隐藏开销）
// 如果你希望“更鲁棒”，可以改为 decode+encode 重建 plaintext（但会引入额外时间，影响 bench）
static inline void ensure_pt_ntt_at_inplace(Evaluator &evaluator,
                                            Plaintext &pt,
                                            const parms_id_type &target_parms_id)
{
    if (pt.parms_id() == target_parms_id)
        return;

    if (pt.parms_id() != seal::parms_id_zero)
    {
        throw invalid_argument("Plaintext has unexpected parms_id (not parms_id_zero / target). Rebuild plaintext instead.");
    }

    evaluator.transform_to_ntt_inplace(pt, target_parms_id);
}

// ------------------------------------------------------------
// main
// ------------------------------------------------------------
int main(int argc, char *argv[])
{
    cout << "╔══════════════════════════════════════════════════════════════════════════════╗" << endl;
    cout << "║                    SEAL Bench 对比测试                                       ║" << endl;
    cout << "╚══════════════════════════════════════════════════════════════════════════════╝" << endl;

    // 参数配置：你要求继续用 {50,50,50}
    const size_t poly_degree = 8192;
    const size_t plain_bits = 20;

    cout << "\n[参数配置]" << endl;
    cout << "  scheme: BGV" << endl;
    cout << "  poly_degree: " << poly_degree << endl;
    cout << "  plain_bits: " << plain_bits << endl;

    EncryptionParameters parms(scheme_type::bgv);
    parms.set_poly_modulus_degree(poly_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_degree, {60, 50, 50}));
    parms.set_plain_modulus(PlainModulus::Batching(poly_degree, plain_bits));

    SEALContext context(parms);

    MemoryPoolHandle pool = MemoryManager::GetPool();
    cout << "  MemoryPool: " << (pool ? "OK" : "FAIL") << endl;

    print_chain_summary(context);

    // keys
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    // tools
    Evaluator evaluator(context);
    BatchEncoder encoder(context);
    size_t slot_count = encoder.slot_count();

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    auto cm_in = parms.coeff_modulus();
cout << "[Input parms] coeff_modulus bits: ";
for (auto &p : cm_in) cout << p.bit_count() << " ";
cout << " (count=" << cm_in.size() << ")\n";

auto cm_ctx = context.first_context_data()->parms().coeff_modulus();
cout << "[Context level0] coeff_modulus bits: ";
for (auto &p : cm_ctx) cout << p.bit_count() << " ";
cout << " (count=" << cm_ctx.size() << ")\n";

cout << "parameters_set=" << context.parameters_set() << "\n";


    cout << "  slot_count: " << slot_count << endl;
    cout << "  plain_modulus: " << parms.plain_modulus().value() << endl;

    random_device rd;
    mt19937_64 gen(rd());
     // ====== 打印 decomposition 规模 ======
    print_kswitch_decomp("RelinKeys", relin_keys);
    Plaintext plain = make_random_plain_bgv(context, slot_count, parms.plain_modulus().value(), gen, pool);

    // ------------------------------------------------------------
    // 为性能测试准备：手动 randomize 一条 NTT 密文（纯算子）
    // ------------------------------------------------------------
    auto &parms_data = context.first_context_data()->parms();
    const auto &coeff_modulus = parms_data.coeff_modulus();
    uniform_int_distribution<uint64_t> ct_dist(0, coeff_modulus[0].value() - 1);

    vector<Ciphertext> ct(3, Ciphertext(context, pool));
    for (auto &c : ct)
    {
        c.resize(context, 2);
        c.parms_id() = context.first_parms_id();
    }

    auto randomize_ct_ntt = [&](Ciphertext &c)
    {
        for (size_t i = 0; i < c.size(); i++)
        {
            for (size_t j = 0; j < coeff_modulus.size(); j++)
            {
                for (size_t k = 0; k < poly_degree; k++)
                    c.data(i)[j * poly_degree + k] = ct_dist(gen);
            }
        }
        c.is_ntt_form() = true;
        c.parms_id() = context.first_parms_id();
    };

    randomize_ct_ntt(ct[0]);
    randomize_ct_ntt(ct[1]);

    const int test_iterations = 10;

    // ------------------------------------------------------------
    // 1) MultiplyPlainInplace
    // ------------------------------------------------------------
    cout << "\n1. 明密文乘法测试 (MultiplyPlainInplace):" << endl;

    { Ciphertext tmp = ct[0]; evaluator.multiply_plain_inplace(tmp, plain); }

    double mul_pt_avg_us = 0.0;
    {
        double total_us = 0.0;
        for (int i = 0; i < test_iterations; i++)
        {
            randomize_ct_ntt(ct[0]);
            plain = make_random_plain_bgv(context, slot_count, parms.plain_modulus().value(), gen, pool);

            auto t0 = high_resolution_clock::now();
            evaluator.multiply_plain_inplace(ct[0], plain);
            auto t1 = high_resolution_clock::now();
            total_us += duration<double, micro>(t1 - t0).count();
        }
        mul_pt_avg_us = total_us / test_iterations;
    }

    cout << "   测试次数: " << test_iterations << endl;
    cout << "   平均耗时: " << fixed << setprecision(2) << mul_pt_avg_us << " μs" << endl;

    // ------------------------------------------------------------
    // 2) RotateRowsInplace
    // ------------------------------------------------------------
    cout << "\n2. 旋转操作测试 (RotateRowsInplace):" << endl;

    { Ciphertext tmp = ct[0]; evaluator.rotate_rows_inplace(tmp, 1, galois_keys); }

    double rotate_avg_us = 0.0;
    {
        double total_us = 0.0;
        for (int i = 0; i < test_iterations; i++)
        {
            randomize_ct_ntt(ct[0]);
            auto t0 = high_resolution_clock::now();
            evaluator.rotate_rows_inplace(ct[0], 1, galois_keys);
            auto t1 = high_resolution_clock::now();
            total_us += duration<double, micro>(t1 - t0).count();
        }
        rotate_avg_us = total_us / test_iterations;
    }

    cout << "   测试次数: " << test_iterations << endl;
    cout << "   平均耗时: " << fixed << setprecision(2) << rotate_avg_us << " μs" << endl;

    // ------------------------------------------------------------
    // 3) AddInplace
    // ------------------------------------------------------------
    cout << "\n3. 密文加法测试 (AddInplace):" << endl;

    { Ciphertext tmp = ct[0]; evaluator.add_inplace(tmp, ct[1]); }

    double add_avg_us = 0.0;
    {
        double total_us = 0.0;
        for (int i = 0; i < test_iterations; i++)
        {
            randomize_ct_ntt(ct[0]);
            randomize_ct_ntt(ct[1]);
            auto t0 = high_resolution_clock::now();
            evaluator.add_inplace(ct[0], ct[1]);
            auto t1 = high_resolution_clock::now();
            total_us += duration<double, micro>(t1 - t0).count();
        }
        add_avg_us = total_us / test_iterations;
    }

    cout << "   测试次数: " << test_iterations << endl;
    cout << "   平均耗时: " << fixed << setprecision(2) << add_avg_us << " μs" << endl;

    // ------------------------------------------------------------
    // 4) ModSwitchToNextInplace 性能（真实加密密文）
    // ------------------------------------------------------------
    cout << "\n4. ModSwitch 测试 (ModSwitchToNextInplace):" << endl;

    Plaintext pt0 = make_random_plain_bgv(context, slot_count, parms.plain_modulus().value(), gen, pool);
    Ciphertext enc_ct;
    encryptor.encrypt(pt0, enc_ct);

    // warmup
    {
        Ciphertext tmp = enc_ct;
        auto d = context.get_context_data(tmp.parms_id());
        if (d && d->next_context_data())
            evaluator.mod_switch_to_next_inplace(tmp);
    }

    double modswitch_avg_us = time_us([&](){
        Ciphertext tmp = enc_ct;
        auto d = context.get_context_data(tmp.parms_id());
        if (d && d->next_context_data())
            evaluator.mod_switch_to_next_inplace(tmp);
    }, test_iterations);

    cout << "   测试次数: " << test_iterations << endl;
    cout << "   平均耗时: " << fixed << setprecision(2) << modswitch_avg_us << " μs" << endl;

    // ------------------------------------------------------------
    // 5) 噪声预算 & 连续 modswitch
    // ------------------------------------------------------------
    cout << "\n5. 噪声预算 & ModSwitch 次数消耗分析:" << endl;

    Plaintext pt_noise = make_random_plain_bgv(context, slot_count, parms.plain_modulus().value(), gen, pool);
    Ciphertext ct_noise;
    encryptor.encrypt(pt_noise, ct_noise);

    int nb0 = decryptor.invariant_noise_budget(ct_noise);
    cout << "   初始 noise_budget = " << nb0 << " bits" << endl;

    size_t ms_count = 0;
    int min_nb = nb0;

    while (true)
    {
        auto data = context.get_context_data(ct_noise.parms_id());
        if (!data || !data->next_context_data())
            break;

        evaluator.mod_switch_to_next_inplace(ct_noise);
        ms_count++;

        int nb = decryptor.invariant_noise_budget(ct_noise);
        min_nb = std::min(min_nb, nb);

        cout << "   after modswitch #" << ms_count
             << " noise_budget = " << nb << " bits" << endl;
    }

    size_t levels = count_modswitch_levels(context);
    cout << "   实际执行 modswitch 次数 = " << ms_count
         << " / 理论上限 " << (levels > 0 ? levels - 1 : 0) << endl;
    cout << "   modswitch 过程中 min_noise_budget = " << min_nb << " bits" << endl;

    // ------------------------------------------------------------
    // 6) PIR-like Noise Trace
    // 需求：
    // - rotate 后进行明文乘法，然后相加 n1 次，打印 budget
    // - 进行一次旋转并相加 n2 次（giant-step风格），打印 budget
    // - 进行一次 modswitch，打印 budget
    // - 将该结果与新的旋转后的密文（需要执行一次 modswitch）做一次 multiply(size=3)，打印 budget
    // - 相加 dim2n1 次，打印 budget
    // - 重线性化+模切换分别打印 budget
    // - 再做一次旋转并相加 dim2n2 次，打印 budget
    // ------------------------------------------------------------
    cout << "\n6. PIR-like Noise Trace:" << endl;

    const size_t n1 = 128;
    const size_t n2 = 8;
    const size_t dim2n1 = 4;
    const size_t dim2n2 = 4;

    // 6.0 base ct + pt（真实加密）
    Plaintext pt_base = make_random_plain_bgv(context, slot_count, parms.plain_modulus().value(), gen, pool);
    Ciphertext ct_base;
    encryptor.encrypt(pt_base, ct_base);

    // 避免重复 NTT 转换（你遇到的 crash 就来自这里）
    ensure_ct_ntt_inplace(evaluator, ct_base);

    // 明文转换到与 ct_base 相同 level 的 NTT（只做一次）
    Plaintext pt_ntt = pt_base;
    ensure_pt_ntt_at_inplace(evaluator, pt_ntt, ct_base.parms_id());

    print_budget("start(base_ct NTT)", context, decryptor, ct_base);

    // 6.1 rotate -> mul_plain -> add (n1 次)
    Ciphertext acc1(pool);
    bool acc1_init = false;

    Ciphertext rot(pool);
    Ciphertext tmp(pool);

    for (size_t i = 0; i < n1; ++i)
    {
        if (i == 0)
            rot = ct_base;
        else
            evaluator.rotate_rows(ct_base, static_cast<int>(i), galois_keys, rot);

        evaluator.multiply_plain(rot, pt_ntt, tmp);

        if (!acc1_init)
        {
            acc1 = tmp;
            acc1_init = true;
        }
        else
        {
            evaluator.add_inplace(acc1, tmp);
        }
    }

    print_budget("after n1*(rotate+mul_plain+add)", context, decryptor, acc1);

    // 6.2 giant-step rotate+add：一次旋转并相加 n2 次（等效：acc1 + rotate(acc1, n1) + ...）
    Ciphertext acc2 = acc1;
    for (size_t j = 1; j < n2; ++j)
    {
        Ciphertext rj(pool);
        evaluator.rotate_rows(acc1, static_cast<int>(j * n1), galois_keys, rj);
        evaluator.add_inplace(acc2, rj);
    }

    print_budget("after giant-step (n2 adds)", context, decryptor, acc2);


    // 6.4 新的旋转密文：rotate(ct_base,1)，并执行一次 modswitch，然后对齐 level 后 multiply
    Ciphertext ct_rot_new(pool);
    evaluator.rotate_rows(ct_base, 1, galois_keys, ct_rot_new);

    // 对齐 parms_id（必要）
    align_cipher_to_parms_id_inplace(evaluator, context, ct_rot_new, acc2.parms_id());

    if (ct_rot_new.parms_id() != acc2.parms_id())
    {
        cout << "   [warn] ct_rot_new parms_id != acc2 parms_id, forcing mod_switch_to_inplace attempt." << endl;
        evaluator.mod_switch_to_inplace(ct_rot_new, acc2.parms_id());
    }

    Ciphertext prod(pool);
    evaluator.multiply(acc2, ct_rot_new, prod); // size=3
    print_budget("after ct*ct multiply (size=3)", context, decryptor, prod);

    // 6.5 相加 dim2n1 次：prod + rotate(prod,1) + ... + rotate(prod,dim2n1-1)
    Ciphertext acc3 = prod;
    for (size_t i = 1; i < dim2n1; ++i)
    {
        Ciphertext ri(pool);
        evaluator.rotate_rows(prod, static_cast<int>(i), galois_keys, ri);
        evaluator.add_inplace(acc3, ri);
    }
    print_budget("after dim2n1 rotate+add", context, decryptor, acc3);

    // 6.6 relinearize + modswitch
    evaluator.relinearize_inplace(acc3, relin_keys);
    print_budget("after relinearize", context, decryptor, acc3);

    {
        auto d = context.get_context_data(acc3.parms_id());
        if (d && d->next_context_data())
        {
            evaluator.mod_switch_to_next_inplace(acc3);
            print_budget("after modswitch#2", context, decryptor, acc3);
        }
        else
        {
            cout << "   [warn] cannot modswitch#2 (no next level)" << endl;
        }
    }

    // 6.7 giant-step rotate+add dim2n2 次：acc3 + rotate(acc3, dim2n1) + rotate(acc3, 2*dim2n1) + ...
    Ciphertext acc4 = acc3;
    for (size_t j = 1; j < dim2n2; ++j)
    {
        Ciphertext rj(pool);
        evaluator.rotate_rows(acc3, static_cast<int>(j * dim2n1), galois_keys, rj);
        evaluator.add_inplace(acc4, rj);
    }
    print_budget("after dim2n2 giant-step rotate+add", context, decryptor, acc4);

    // ------------------------------------------------------------
    // 汇总
    // ------------------------------------------------------------
    cout << "\n╔═══════════════════════════════════════════════════════════════╗" << endl;
    cout << "║                  SEAL Bench 对比测试结果                      ║" << endl;
    cout << "╠═══════════════════════════════════════════════════════════════╣" << endl;
    cout << "║  测试项目                         平均耗时(μs)                ║" << endl;
    cout << "╠═══════════════════════════════════════════════════════════════╣" << endl;
    cout << "║  明密文乘法 (MultiplyPlainInplace)   " << setw(12) << fixed << setprecision(2) << mul_pt_avg_us << "          ║" << endl;
    cout << "║  旋转操作 (RotateRowsInplace)        " << setw(12) << fixed << setprecision(2) << rotate_avg_us << "          ║" << endl;
    cout << "║  密文加法 (AddInplace)               " << setw(12) << fixed << setprecision(2) << add_avg_us << "          ║" << endl;
    cout << "║  ModSwitch (ModSwitchToNextInplace)  " << setw(12) << fixed << setprecision(2) << modswitch_avg_us << "          ║" << endl;
    cout << "╚═══════════════════════════════════════════════════════════════╝" << endl;

    cout << "\n[ModSwitch 链分析]" << endl;
    cout << "  coeff_modulus primes bits: {50,50,50}" << endl;
    cout << "  levels = " << levels << " => max_modswitch = " << (levels > 0 ? levels - 1 : 0) << endl;
    cout << "  noise_budget(initial)=" << nb0 << " bits, min_during_modswitch=" << min_nb << " bits" << endl;

    cout << "\nSEAL Bench 对比测试完成!" << endl;
    return 0;
}
