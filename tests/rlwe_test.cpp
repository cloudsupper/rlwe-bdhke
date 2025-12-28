#include <gtest/gtest.h>

#include <rlwe.h>
#include <logging.h>

#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

// Basic tests for the RLWE (kem.cpp) module.
//
// These tests focus on deterministic behavior:
//  - Parameter set selection
//  - Constructors and parameter classification
//  - Hash-to-polynomial mapping
//  - Key generation output structure
//  - Shared secret derivation shape & determinism
//
// We deliberately avoid relying on particular random values.

TEST(KEMParamsTest, ParameterSetsMatchSpec)
{
    RLWEParams tiny = RLWE::getParameterSet(SecurityLevel::TEST_TINY);
    EXPECT_EQ(tiny.n, static_cast<size_t>(8));
    EXPECT_EQ(tiny.q, static_cast<uint64_t>(7681));
    EXPECT_STREQ(tiny.name, "TEST_TINY (INSECURE)");
    EXPECT_EQ(tiny.classical_bits, 4);
    EXPECT_EQ(tiny.quantum_bits, 2);
    EXPECT_FALSE(tiny.is_secure);

    RLWEParams small = RLWE::getParameterSet(SecurityLevel::TEST_SMALL);
    EXPECT_EQ(small.n, static_cast<size_t>(32));
    EXPECT_EQ(small.q, static_cast<uint64_t>(7681));
    EXPECT_STREQ(small.name, "TEST_SMALL (INSECURE)");
    EXPECT_EQ(small.classical_bits, 16);
    EXPECT_EQ(small.quantum_bits, 8);
    EXPECT_FALSE(small.is_secure);

    RLWEParams kyber = RLWE::getParameterSet(SecurityLevel::KYBER512);
    EXPECT_EQ(kyber.n, static_cast<size_t>(256));
    EXPECT_EQ(kyber.q, static_cast<uint64_t>(7681));
    EXPECT_STREQ(kyber.name, "KYBER512-like (NTT-friendly)");
    EXPECT_EQ(kyber.classical_bits, 128);
    EXPECT_EQ(kyber.quantum_bits, 64);
    EXPECT_TRUE(kyber.is_secure);

    RLWEParams moderate = RLWE::getParameterSet(SecurityLevel::MODERATE);
    EXPECT_EQ(moderate.n, static_cast<size_t>(512));
    EXPECT_EQ(moderate.q, static_cast<uint64_t>(12289));
    EXPECT_STREQ(moderate.name, "MODERATE");
    EXPECT_EQ(moderate.classical_bits, 192);
    EXPECT_EQ(moderate.quantum_bits, 96);
    EXPECT_TRUE(moderate.is_secure);

    RLWEParams high = RLWE::getParameterSet(SecurityLevel::HIGH);
    EXPECT_EQ(high.n, static_cast<size_t>(1024));
    EXPECT_EQ(high.q, static_cast<uint64_t>(18433));
    EXPECT_STREQ(high.name, "HIGH");
    EXPECT_EQ(high.classical_bits, 256);
    EXPECT_EQ(high.quantum_bits, 128);
    EXPECT_TRUE(high.is_secure);
}

TEST(KEMConstructorTest, ExplicitParamsAcceptPowerOfTwo)
{
    // n is a power of two -> should construct successfully.
    RLWE kem(8, 7681);
    RLWEParams p = kem.getParameters();

    EXPECT_EQ(p.n, static_cast<size_t>(8));
    EXPECT_EQ(p.q, static_cast<uint64_t>(7681));
}

TEST(KEMConstructorTest, ThrowsOnNonPowerOfTwoDimension)
{
    EXPECT_THROW((RLWE(7, 7681)), std::invalid_argument);
    EXPECT_THROW((RLWE(0, 7681)), std::invalid_argument);
}

TEST(KEMConstructorTest, SecurityLevelConstructorMatchesParameterSet)
{
    auto check_level = [](SecurityLevel level) {
        RLWEParams params = RLWE::getParameterSet(level);
        RLWE kem(level);
        RLWEParams active = kem.getParameters();

        EXPECT_EQ(active.n, params.n);
        EXPECT_EQ(active.q, params.q);

        // is_secure should be consistent with the heuristic in getParameters().
        EXPECT_EQ(active.is_secure, params.is_secure);
    };

    check_level(SecurityLevel::TEST_TINY);
    check_level(SecurityLevel::TEST_SMALL);
    check_level(SecurityLevel::KYBER512);
    check_level(SecurityLevel::MODERATE);
    check_level(SecurityLevel::HIGH);
}

TEST(KEMGetParametersTest, ClassifiesSecurityByRingDimension)
{
    {
        // n < 128
        RLWE kem(64, 7681);
        RLWEParams p = kem.getParameters();
        EXPECT_EQ(p.classical_bits, static_cast<int>(64 * 0.5));
        EXPECT_EQ(p.quantum_bits, static_cast<int>(64 * 0.25));
        EXPECT_FALSE(p.is_secure);
    }

    {
        // 128 <= n < 256
        RLWE kem(128, 7681);
        RLWEParams p = kem.getParameters();
        EXPECT_EQ(p.classical_bits, 80);
        EXPECT_EQ(p.quantum_bits, 40);
        EXPECT_FALSE(p.is_secure);
    }

    {
        // n >= 256
        RLWE kem(256, 7681);
        RLWEParams p = kem.getParameters();
        EXPECT_EQ(p.classical_bits, static_cast<int>(256 * 0.6));
        EXPECT_EQ(p.quantum_bits, static_cast<int>(256 * 0.3));
        EXPECT_TRUE(p.is_secure);
    }
}

TEST(KEMKeyGenTest, GeneratesPolynomialsWithCorrectShape)
{
    // Use the HIGH security parameter set.
    RLWE kem(SecurityLevel::HIGH);
    RLWEParams params = RLWE::getParameterSet(SecurityLevel::HIGH);

    kem.generateKeys();

    auto b = kem.getPublicKey();
    Polynomial s = kem.getSecretKeyForTesting();

    for (const auto& poly : {b, s}) {
        EXPECT_EQ(poly.degree(), params.n);
        EXPECT_EQ(poly.getModulus(), params.q);
    }
}

TEST(KEMHashToPolynomialTest, CoefficientsAreZeroOrHalfQ)
{
    RLWE kem(SecurityLevel::HIGH);
    RLWEParams params = RLWE::getParameterSet(SecurityLevel::HIGH);

    std::vector<uint8_t> message = {0x01, 0x02, 0x03};
    Polynomial p = kem.hashToPolynomial(message);

    const auto& coeffs = p.getCoeffs();
    ASSERT_EQ(coeffs.size(), params.n);

    uint64_t zero = 0;
    uint64_t half_q = params.q / 2;

    for (auto c : coeffs) {
        EXPECT_TRUE(c == zero || c == half_q)
            << "Coefficient " << c << " is not 0 or q/2";
    }
}

TEST(KEMHashToPolynomialTest, DeterministicForSameMessage)
{
    RLWE kem(SecurityLevel::HIGH);
    std::vector<uint8_t> message = {'t', 'e', 's', 't'};

    Polynomial p1 = kem.hashToPolynomial(message);
    Polynomial p2 = kem.hashToPolynomial(message);

    EXPECT_EQ(p1.getCoeffs(), p2.getCoeffs());
}

TEST(KEMHashToPolynomialTest, DifferentMessagesUsuallyDifferentPolynomials)
{
    RLWE kem(SecurityLevel::HIGH);
    std::vector<uint8_t> msg1 = {'a', 'b', 'c'};
    std::vector<uint8_t> msg2 = {'a', 'b', 'd'};

    Polynomial p1 = kem.hashToPolynomial(msg1);
    Polynomial p2 = kem.hashToPolynomial(msg2);

    // Extremely unlikely to collide; treat equality as test failure.
    EXPECT_NE(p1.getCoeffs(), p2.getCoeffs());
}

TEST(KEMSharedSecretTest, SharedSecretAgreement)
{
    // Use HIGH security level for this functional test.
    RLWE kem_1(SecurityLevel::HIGH);
    RLWE kem_2(SecurityLevel::HIGH);
    kem_1.generateKeys();
    kem_2.generateKeys();

    auto b_1 = kem_1.getPublicKey();
    auto b_2 = kem_2.getPublicKey();

    std::vector<uint8_t> ss_a = kem_1.getSharedSecret(b_2);
    std::vector<uint8_t> ss_b = kem_2.getSharedSecret(b_1);

    EXPECT_EQ(ss_a.size(), ss_b.size());
    for (size_t i=0; i<ss_a.size(); ++i) {
        EXPECT_EQ(ss_a[i], ss_b[i]);
    }
}

TEST(KEMLoggingTest, ValidateSecurityParametersEmitsMessagesWhenEnabled)
{
    // Capture log output into a stringstream.
    std::stringstream ss;
    std::ostream* previous = Logger::out;

    Logger::setOutputStream(ss);
    Logger::enable_logging = true;

    {
        // Constructor calls validateSecurityParameters() internally.
        RLWE kem(SecurityLevel::HIGH);
        (void)kem;
    }

    Logger::enable_logging = false;
    if (previous) {
        Logger::setOutputStream(*previous);
    }

    std::string log_output = ss.str();
    EXPECT_NE(log_output.find("Validating security parameters"), std::string::npos);
    EXPECT_NE(log_output.find("Ring dimension (n):"), std::string::npos);
}
