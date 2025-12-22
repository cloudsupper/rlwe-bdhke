#include <gtest/gtest.h>
#include <polynomial.h>

class PolynomialTest : public ::testing::Test {
protected:
    const size_t n = 2;
    const uint64_t q = 17;
};

TEST_F(PolynomialTest, ToBytes) {
    Polynomial p(4, 17);
    std::vector<uint64_t> coeffs = {1, 2, 3, 4};
    p.setCoefficients(coeffs);
    
    auto bytes = p.toBytes();
    
    size_t expected_size = sizeof(size_t) + sizeof(uint64_t) + 4 * sizeof(uint64_t);
    EXPECT_EQ(bytes.size(), expected_size);
    
    Polynomial p2(4, 17);
    p2.setCoefficients(coeffs);
    
    EXPECT_EQ(p.toBytes(), p2.toBytes());
    
    std::vector<uint64_t> coeffs2 = {1, 2, 3, 5};
    p2.setCoefficients(coeffs2);
    
    EXPECT_NE(p.toBytes(), p2.toBytes());
}

TEST_F(PolynomialTest, Addition) {
    Polynomial f({1, 2, 3, 4}, q);
    Polynomial g({5, 6, 7, 8}, q);
    
    Polynomial h = f + g;
    
    EXPECT_EQ(h[0], 6);
    EXPECT_EQ(h[1], 8);
    EXPECT_EQ(h[2], 10);
    EXPECT_EQ(h[3], 12);
}


TEST_F(PolynomialTest, Subtraction) {
    Polynomial f({1, 2, 3, 4}, q);
    Polynomial g({5, 6, 7, 8}, q);

    Polynomial h = f - g;

    EXPECT_EQ(h[0], 13u);
    EXPECT_EQ(h[1], 13u);
    EXPECT_EQ(h[2], 13u);
    EXPECT_EQ(h[3], 13u);
}

TEST_F(PolynomialTest, Negation) {
    Polynomial p({0, 1, 16, 8}, q);

    Polynomial neg = -p;
    EXPECT_EQ(neg[0], 0u);
    EXPECT_EQ(neg[1], 16u);
    EXPECT_EQ(neg[2], 1u);
    EXPECT_EQ(neg[3], 9u);
}

TEST_F(PolynomialTest, MultiplicationByOneAndZero) {
    Polynomial one({1, 0, 0, 0}, q);
    Polynomial zero({0, 0, 0, 0}, q);
    Polynomial f({3, 5, 7, 9}, q);

    Polynomial f_times_one = f * one;
    Polynomial one_times_f = one * f;
    Polynomial f_times_zero = f * zero;
    Polynomial zero_times_f = zero * f;

    for (size_t i = 0; i < f.degree(); ++i) {
        EXPECT_EQ(f_times_one[i], f[i]);
        EXPECT_EQ(one_times_f[i], f[i]);
        EXPECT_EQ(f_times_zero[i], 0u);
        EXPECT_EQ(zero_times_f[i], 0u);
    }
}

TEST_F(PolynomialTest, MultiplicationWrapAroundX4Plus1) {
    Polynomial x({0, 1, 0, 0}, q);
    Polynomial x3({0, 0, 0, 1}, q);

    Polynomial prod1 = x * x3;
    Polynomial prod2 = x3 * x;

    EXPECT_EQ(prod1[0], 16u);
    EXPECT_EQ(prod1[1], 0u);
    EXPECT_EQ(prod1[2], 0u);
    EXPECT_EQ(prod1[3], 0u);

    EXPECT_EQ(prod2[0], 16u);
    EXPECT_EQ(prod2[1], 0u);
    EXPECT_EQ(prod2[2], 0u);
    EXPECT_EQ(prod2[3], 0u);
}

TEST_F(PolynomialTest, ScalarMultiplication) {
    Polynomial f({1, 2, 3, 4}, q);
    uint64_t scalar = 5;

    Polynomial h = f * scalar;

    EXPECT_EQ(h[0], 5u);
    EXPECT_EQ(h[1], 10u);
    EXPECT_EQ(h[2], 15u);
    EXPECT_EQ(h[3], 3u);
}

TEST_F(PolynomialTest, PolySignalRounding) {
    Polynomial p({0, 4, 5, 7, 8, 9, 13, 16}, q);

    Polynomial s = p.polySignal();

    std::vector<uint64_t> expected = {0, 0, 8, 8, 8, 8, 0, 0};
    ASSERT_EQ(s.degree(), expected.size());
    for (size_t i = 0; i < expected.size(); ++i) {
        EXPECT_EQ(s[i], expected[i]) << "Mismatch at index " << i;
    }
}

TEST_F(PolynomialTest, SetCoefficientsModReductionAndSizeCheck) {
    Polynomial p(4, q);

    std::vector<uint64_t> coeffs = {q + 1, 2 * q, 0, q - 1};
    p.setCoefficients(coeffs);

    EXPECT_EQ(p[0], 1u);
    EXPECT_EQ(p[1], 0u);
    EXPECT_EQ(p[2], 0u);
    EXPECT_EQ(p[3], (q - 1));

    std::vector<uint64_t> wrong_size = {1, 2, 3};
    EXPECT_THROW(p.setCoefficients(wrong_size), std::invalid_argument);
}

TEST_F(PolynomialTest, RingDimensionAndModulusAccessors) {
    Polynomial p({1, 2, 3, 4}, q);

    EXPECT_EQ(p.degree(), 4u);
    EXPECT_EQ(p.getModulus(), q);
}

TEST_F(PolynomialTest, OperationsRequireSameRingAndModulus) {
    Polynomial f({1, 2, 3, 4}, q);
    Polynomial different_dim({1, 2}, q);       // ring_dim = 2
    Polynomial different_mod({1, 2, 3, 4}, q + 1);  // same dim, different modulus

    EXPECT_THROW(f + different_dim, std::invalid_argument);
    EXPECT_THROW(f - different_dim, std::invalid_argument);
    EXPECT_THROW(f * different_dim, std::invalid_argument);

    EXPECT_THROW(f + different_mod, std::invalid_argument);
    EXPECT_THROW(f - different_mod, std::invalid_argument);
    EXPECT_THROW(f * different_mod, std::invalid_argument);
}
