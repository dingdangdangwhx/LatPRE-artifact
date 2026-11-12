// Single-hop CiC 2025 / OpenFHE public-API comparison benchmark.
// Serialization and correctness checks are outside algorithm timing intervals.
#include "openfhe.h"
#include "gen-cryptocontext.h"
#include "utils/serial.h"
#include "key/key-ser.h"
#include "cryptocontext-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <sys/utsname.h>

#ifndef CIC_OPENFHE_VARIANT
#define CIC_OPENFHE_VARIANT "unspecified"
#endif
#ifndef CIC_OPENFHE_VERSION
#define CIC_OPENFHE_VERSION "unknown"
#endif

using namespace lbcrypto;
using Clock = std::chrono::steady_clock;

struct Options {
    std::string mode = "hra", ks = "hybrid", output = "cic25";
    uint32_t ring = 4096, hops = 1, samples = 1000, warmup = 10;
    uint32_t digit = 0, parts = 1, firstMod = 0;
    uint32_t nu = 48, tauLog2 = 18;
    bool ringSet = false, digitSet = false, sourcePk = true;
};

static std::string quote(const std::string& s) {
    std::ostringstream out;
    out << '"';
    for (unsigned char c : s) {
        switch (c) {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (c < 32) out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << unsigned(c) << std::dec;
                else out << c;
        }
    }
    out << '"';
    return out.str();
}

static uint32_t number(const std::string& s) {
    size_t used = 0;
    auto n = std::stoull(s, &used);
    if (used != s.size() || n > UINT32_MAX) throw std::runtime_error("Invalid integer: " + s);
    return static_cast<uint32_t>(n);
}

static Options parse(int argc, char** argv) {
    Options o;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--help") {
            std::cout << "--samples N --warmup N --output PREFIX\n"
                         "Fixed profile: HRA/HYBRID, N4096, one hop, p2, 256-bit message,\n"
                         "nu48, tau2^18, classic128, ternary secret, sigma3.2.\n"
                         "Defaults: 1000 measurements and 10 warmups per operation.\n";
            std::exit(0);
        }
        if (i + 1 == argc) throw std::runtime_error("Missing value for " + a);
        std::string v = argv[++i];
        if (a == "--samples") o.samples = number(v);
        else if (a == "--warmup") o.warmup = number(v);
        else if (a == "--output") o.output = v;
        else throw std::runtime_error("Unknown option " + a);
    }
    if (!o.samples || o.samples > 100000 || o.warmup > 100000)
        throw std::runtime_error("Invalid samples or warmup count");
    return o;
}

static CCParams<CryptoContextBGVRNS> parameters(const Options& o) {
    CCParams<CryptoContextBGVRNS> p;
    p.SetPREMode(o.mode == "hra" ? NOISE_FLOODING_HRA : INDCPA);
    p.SetKeySwitchTechnique(o.ks == "hybrid" ? HYBRID : BV);
    if (o.mode == "hra") p.SetPRENumHops(o.hops);
    p.SetScalingTechnique(FIXEDMANUAL);
    p.SetMultiplicativeDepth(0);
    // This profile performs PRE only, with no homomorphic additions or
    // additional key switches requested from the parameter generator.
    p.SetEvalAddCount(0);
    p.SetKeySwitchCount(0);
    p.SetPlaintextModulus(2);
    p.SetStandardDeviation(3.2f);
    p.SetSecretKeyDist(UNIFORM_TERNARY);
    p.SetSecurityLevel(HEStd_128_classic);
    p.SetRingDim(o.ring);
    p.SetDigitSize(o.digit);
    if (o.ks == "hybrid") p.SetNumLargeDigits(o.parts);
    if (o.firstMod) p.SetFirstModSize(o.firstMod);
    if (o.mode == "hra") {
        p.SetStatisticalSecurity(o.nu);
        p.SetNumAdversarialQueries(uint32_t(1) << o.tauLog2);
    }
    return p;
}

static CryptoContext<DCRTPoly> setup(const Options& o) {
    auto cc = GenCryptoContext(parameters(o));
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(PRE);
    return cc;
}

using Measurements = std::map<std::string, std::vector<uint64_t>>;
template <class Before, class Operation, class Check>
static void measure(Measurements& all, const Options& o, const std::string& name,
                    Before before, Operation operation, Check check) {
    for (uint32_t i = 0; i < o.warmup + o.samples; ++i) {
        before();
        const auto t0 = Clock::now();
        auto result = operation();
        const auto t1 = Clock::now();
        check(result); // Includes complete decryption checks when applicable.
        if (i >= o.warmup) all[name].push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(t1-t0).count());
    }
    std::cerr << "Completed " << name << '\n';
}
template <class Operation, class Check>
static void measure(Measurements& all, const Options& o, const std::string& name, Operation op, Check check) {
    measure(all, o, name, [](){}, op, check);
}

struct Decoded { DecryptResult result; Plaintext plaintext; };
static Decoded decrypt(CryptoContext<DCRTPoly> cc, const PrivateKey<DCRTPoly>& sk,
                       const Ciphertext<DCRTPoly>& ct) {
    Decoded d;
    d.result = cc->Decrypt(sk, ct, &d.plaintext);
    return d;
}
static void checkMessage(Decoded d, const std::vector<int64_t>& expected) {
    if (!d.result.isValid || !d.plaintext) throw std::runtime_error("Invalid decrypt result");
    d.plaintext->SetLength(expected.size());
    const auto& actual = d.plaintext->GetCoefPackedValue();
    if (actual.size() < expected.size()) throw std::runtime_error("Truncated full-ring plaintext");
    for (size_t i = 0; i < expected.size(); ++i) {
        int64_t bit = ((actual[i] % 2) + 2) % 2;
        if (bit != expected[i]) throw std::runtime_error("Full-ring plaintext/padding mismatch at index " + std::to_string(i));
    }
}

template <class Object> static size_t standaloneBytes(const Object& obj) {
    std::ostringstream stream(std::ios::out | std::ios::binary);
    Serial::Serialize(obj, stream, SerType::BINARY);
    return stream.str().size();
}
template <class Object> static size_t incrementalBytes(CryptoContext<DCRTPoly> cc, const Object& obj) {
    std::ostringstream stream(std::ios::out | std::ios::binary);
    cereal::PortableBinaryOutputArchive archive(stream);
    archive(cc);
    size_t prefix = stream.str().size();
    archive(obj);
    return stream.str().size() - prefix;
}

static std::string basis(const std::shared_ptr<ILDCRTParams<BigInteger>>& p) {
    if (!p) return "null";
    std::ostringstream out;
    out << std::setprecision(17) << "{\"limbs\":" << p->GetParams().size()
        << ",\"product_bits\":" << p->GetModulus().GetMSB() << ",\"log2_product\":";
    double logq = 0;
    for (const auto& limb : p->GetParams()) logq += std::log2(static_cast<double>(limb->GetModulus().ConvertToInt()));
    out << logq << ",\"primes_decimal\":[";
    bool first = true;
    for (const auto& limb : p->GetParams()) {
        if (!first) out << ',';
        first = false;
        out << quote(limb->GetModulus().ToString());
    }
    out << "]}";
    return out.str();
}

static std::string ciphertextInfo(const Ciphertext<DCRTPoly>& ct) {
    if (!ct || ct->GetElements().empty()) return "null";
    std::ostringstream out;
    out << "{\"components\":" << ct->GetElements().size() << ",\"level\":" << ct->GetLevel()
        << ",\"basis\":" << basis(ct->GetElements()[0].GetParams()) << '}';
    return out.str();
}

struct Stats { double mean = 0, median = 0; uint64_t min = 0, p95 = 0; };
static Stats stats(std::vector<uint64_t> v) {
    Stats s;
    if (v.empty()) return s;
    for (auto n : v) s.mean += static_cast<double>(n) / v.size();
    std::sort(v.begin(), v.end());
    s.min = v.front();
    s.median = v.size()%2 ? double(v[v.size()/2]) : (double(v[v.size()/2-1])+v[v.size()/2])/2;
    s.p95 = v[static_cast<size_t>(std::ceil(.95*v.size()))-1];
    return s;
}

static std::string machine() {
    struct utsname u;
    if (uname(&u)) return "unknown";
    return std::string(u.sysname) + " " + u.release + " " + u.machine;
}

int main(int argc, char** argv) {
    Options o;
    std::string failure;
    Measurements timings;
    std::map<std::string, std::pair<size_t, size_t>> sizes;
    std::map<std::string, std::string> info;
    try {
        o = parse(argc, argv);
        CryptoContext<DCRTPoly> cc;
        measure(timings, o, "Setup", [&](){ cc.reset(); CryptoContextFactory<DCRTPoly>::ReleaseAllContexts(); },
                [&](){ return setup(o); }, [&](const auto& x){ cc=x; });
        auto cp = std::dynamic_pointer_cast<CryptoParametersBGVRNS>(cc->GetCryptoParameters());
        if (!cp || cc->GetRingDimension() != 4096 ||
            cp->GetElementParams()->GetModulus().GetMSB() != 54 ||
            cp->GetParamsP()->GetModulus().GetMSB() != 55)
            throw std::runtime_error("Library does not implement the pinned single-hop Q54/P55 profile");
#ifdef _OPENMP
        throw std::runtime_error("The comparison must be built with OpenMP disabled");
#endif
        info["ring_dimension"] = std::to_string(cc->GetRingDimension());
        info["Q"] = basis(cp->GetElementParams());
        info["P"] = basis(cp->GetParamsP());
        info["QP"] = basis(cp->GetParamsQP());
        info["PK_basis"] = basis(cp->GetParamsPK());
        info["num_large_digits_actual"] = std::to_string(cp->GetNumPartQ());
        info["digit_size_actual"] = std::to_string(cp->GetDigitSize());
        info["aux_bits"] = std::to_string(cp->GetAuxBits());
        auto real = [](double x){ std::ostringstream s; s << std::setprecision(17) << x; return s.str(); };
        info["error_stddev"] = real(cp->GetDistributionParameter());
        info["error_sampler_stddev"] = real(cp->GetDiscreteGaussianGenerator().GetStd());
        info["flooding_stddev"] = real(cp->GetFloodingDistributionParameter());
        info["flooding_sampler_stddev"] = real(cp->GetFloodingDiscreteGaussianGenerator().GetStd());
        info["assurance_measure"] = real(cp->GetAssuranceMeasure());
        info["statistical_security"] = real(cp->GetStatisticalSecurity());
        info["adversarial_queries"] = real(cp->GetNumAdversarialQueries());
        info["security_level_enum"] = std::to_string(static_cast<unsigned>(cp->GetStdLevel()));
        info["secret_distribution_enum"] = std::to_string(static_cast<unsigned>(cp->GetSecretKeyDist()));
        sizes["context"] = {standaloneBytes(cc), 0};
        KeyPair<DCRTPoly> alice, bob;
        measure(timings, o, "KeyGen", [&](){ return cc->KeyGen(); }, [&](const auto& x){
            if (!x.good()) throw std::runtime_error("KeyGen failure"); alice = x;
        });
        bob = cc->KeyGen();
        auto remember = [&](const std::string& name, const auto& obj){
            sizes[name] = {standaloneBytes(obj), incrementalBytes(cc, obj)};
        };
        remember("public_key", alice.publicKey);
        remember("secret_key", alice.secretKey);
        info["actual_public_key_polynomials"] = std::to_string(alice.publicKey->GetPublicElements().size());
        info["public_key_b_native_payload_bytes"] = std::to_string(
            cc->GetRingDimension() * alice.publicKey->GetPublicElements().at(0).GetParams()->GetParams().size() * sizeof(uint64_t));
        info["actual_public_key_basis"] = basis(alice.publicKey->GetPublicElements().at(0).GetParams());
        info["actual_secret_key_basis"] = basis(alice.secretKey->GetPrivateElement().GetParams());
        std::vector<int64_t> message(256);
        for (size_t i=0; i<message.size(); ++i) message[i] = ((i*17 + i/7 + 3) % 5) & 1;
        std::vector<int64_t> expected(cc->GetRingDimension(), 0);
        std::copy(message.begin(), message.end(), expected.begin());
        auto pt = cc->MakeCoefPackedPlaintext(message);
        Ciphertext<DCRTPoly> source, re, reduced;
        measure(timings, o, "Enc", [&](){ return cc->Encrypt(alice.publicKey, pt); }, [&](const auto& x){
            checkMessage(decrypt(cc, alice.secretKey, x), expected); source=x;
        });
        measure(timings, o, "DecSource", [&](){ return decrypt(cc, alice.secretKey, source); },
                [&](auto d){ checkMessage(d, expected); });
        EvalKey<DCRTPoly> rk;
        measure(timings, o, "ReKeyGen", [&](){ return cc->ReKeyGen(alice.secretKey, bob.publicKey); },
                [&](const auto& x){ if (!x) throw std::runtime_error("Null rekey"); rk=x; });
        auto reencrypt = [&](){
            return o.sourcePk ? cc->ReEncrypt(source, rk, alice.publicKey) : cc->ReEncrypt(source, rk);
        };
        measure(timings, o, "ReEnc", reencrypt, [&](const auto& x){
            checkMessage(decrypt(cc, bob.secretKey, x), expected); re=x;
        });
        measure(timings, o, "DecTerminal", [&](){ return decrypt(cc, bob.secretKey, re); },
                [&](auto d){ checkMessage(d, expected); });
        remember("rekey", rk);
        remember("source_ciphertext", source);
        remember("re_ciphertext", re);
        if (reduced) remember("reduced_re_ciphertext", reduced);
        info["source_ciphertext"] = ciphertextInfo(source);
        info["re_ciphertext"] = ciphertextInfo(re);
        info["reduced_re_ciphertext"] = ciphertextInfo(reduced);
        info["rekey_A_polynomials"] = std::to_string(rk->GetAVector().size());
        info["rekey_B_polynomials"] = std::to_string(rk->GetBVector().size());
        if (!rk->GetAVector().empty()) info["rekey_basis"] = basis(rk->GetAVector().front().GetParams());
    }
    catch (const std::exception& e) { failure = e.what(); std::cerr << "FAILED: " << failure << '\n'; }

    std::ofstream json(o.output + ".json");
    std::ofstream csv(o.output + ".csv");
    if (!json || !csv) { std::cerr << "Cannot open output files\n"; return 2; }
    json << std::setprecision(17) << "{\n  \"schema\":\"cic-openfhe-n4096-bench-v1\",\n"
         << "  \"status\":" << quote(failure.empty()?"ok":"error") << ",\n"
         << "  \"error\":" << (failure.empty()?"null":quote(failure)) << ",\n"
         << "  \"library_variant\":" << quote(CIC_OPENFHE_VARIANT) << ",\n"
         << "  \"library_version\":" << quote(CIC_OPENFHE_VERSION) << ",\n"
         << "  \"compiler\":" << quote(__VERSION__) << ",\n"
         << "  \"machine\":" << quote(machine()) << ",\n"
         << "  \"hardware_concurrency\":" << std::thread::hardware_concurrency() << ",\n"
#ifdef _OPENMP
         << "  \"openmp_compiled\":true,\n"
#else
         << "  \"openmp_compiled\":false,\n"
#endif
         << "  \"timer\":\"std::chrono::steady_clock\",\n"
         << "  \"timer_is_steady\":" << (Clock::is_steady?"true":"false") << ",\n"
         << "  \"timer_period_num\":" << Clock::period::num << ",\n"
         << "  \"timer_period_den\":" << Clock::period::den << ",\n"
         << "  \"config\":{\"mode\":" << quote(o.mode) << ",\"key_switch\":" << quote(o.ks)
         << ",\"requested_ring_dimension\":" << o.ring << ",\"configured_hops\":" << o.hops
         << ",\"measured_hop\":1,\"chain_execution\":\"single edge at full modulus\""
         << ",\"requested_eval_add_count\":0,\"requested_key_switch_count\":0"
         << ",\"source_public_key_enc0\":" << (o.sourcePk?"true":"false")
         << ",\"plaintext_modulus\":2,\"message_bits\":256,\"nu\":" << o.nu
         << ",\"tau_log2\":" << o.tauLog2 << ",\"samples\":" << o.samples << ",\"warmup\":" << o.warmup
         << ",\"hra_budget_applied\":" << (o.mode=="hra"?"true":"false")
         << ",\"requested_digit_size\":" << o.digit << ",\"requested_large_digits\":" << o.parts
         << ",\"requested_first_mod_size\":" << o.firstMod
         << ",\"secret_distribution\":\"UNIFORM_TERNARY\",\"security_level\":\"HEStd_128_classic\"},\n"
         << "  \"security_scope\":" << quote(o.mode=="hra" && !o.ring ?
             "DIAGNOSTIC ONLY: v1.2.0 HRA automatic-ring flooding initialized with N=0" :
             "OpenFHE classic128 parameter check; no claim of quantum128 or certified DFR; sampler approximation not newly certified") << ",\n"
         << "  \"timing_scope\":\"Public API including crypto sampling; excludes serialization, fixture creation, result destruction and correctness checks\",\n"
         << "  \"setup_factory_reset_outside_timer\":true,\n"
         << "  \"randomness\":\"Unmodified OpenFHE PRNG; no fixed crypto seeds\",\n"
         << "  \"message_validation\":\"All N coefficients checked modulo 2 after every measured and warmup Enc/ReEnc and Decrypt: first 256 equal the message, remaining N-256 are zero padding; checks outside timing\",\n"
         << "  \"serialization\":{\"format\":\"OpenFHE SerType::BINARY / Cereal PortableBinary\","
            "\"standalone_scope\":\"Fresh archive per object: includes embedded shared context, polynomial params, key tag and metadata\","
            "\"incremental_scope\":\"Additional object bytes after context in one shared archive; pointer deduplication, not a standalone context-free wire format\"},\n"
         << "  \"parameters\":{";
    bool first = true;
    for (const auto& x : info) { if (!first) json << ','; first=false; json << '\n' << "    " << quote(x.first) << ':' << x.second; }
    json << "\n  },\n  \"sizes_bytes\":{";
    first=true;
    for (const auto& x : sizes) {
        if (!first) json << ','; first=false;
        json << '\n' << "    " << quote(x.first) << ":{\"standalone\":" << x.second.first
             << ",\"incremental_after_context\":" << (x.first=="context"?"null":std::to_string(x.second.second)) << '}';
    }
    json << "\n  },\n  \"operations\":{";
    csv << "operation,sample_index,ns\n";
    first=true;
    const std::vector<std::string> ops={"Setup","KeyGen","Enc","DecSource","ReKeyGen","ReEnc","DecTerminal"};
    for (const auto& name : ops) {
        if (!first) json << ','; first=false;
        json << '\n' << "    " << quote(name) << ":{";
        auto it=timings.find(name);
        if (it==timings.end()) {
            json << "\"status\":\"not_run\",\"raw_ns\":[],\"mean_ns\":null,\"median_ns\":null,\"min_ns\":null,\"p95_ns\":null}";
            continue;
        }
        const auto& v=it->second;
        Stats s=stats(v);
        json << "\"status\":" << quote(v.size()==o.samples?"ok":"partial") << ",\"mean_ns\":" << s.mean << ",\"median_ns\":" << s.median
             << ",\"min_ns\":" << s.min << ",\"p95_ns\":" << s.p95 << ",\"raw_ns\":[";
        for (size_t i=0;i<v.size();++i) {
            if (i) json << ','; json << v[i]; csv << name << ',' << i << ',' << v[i] << '\n';
        }
        json << "]}";
    }
    json << "\n  }\n}\n";
    std::cerr << "Wrote " << o.output << ".json and .csv\n";
    return failure.empty()?0:1;
}
