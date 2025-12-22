#include <gtest/gtest.h>
#include <sha256.h>
#include <openssl/sha.h>
#include <vector>
#include <iomanip>
#include <sstream>
#include <string>

std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

TEST(SHA256Test, HashEmptyString) {
    std::string empty;
    auto hash = SHA256::hash(empty);
    std::string expected =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    EXPECT_EQ(bytesToHex(hash), expected);
}

TEST(SHA256Test, HashSimpleString) {
    std::string msg = "hello world";
    auto hash = SHA256::hash(msg);
    std::string expected =
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
    EXPECT_EQ(bytesToHex(hash), expected);
}

TEST(SHA256Test, HashBytes) {
    std::vector<uint8_t> data = {0x00, 0x01, 0x02, 0x03};
    auto hash = SHA256::hash(data);
    EXPECT_EQ(hash.size(), SHA256::hashSize());
}

TEST(SHA256Test, HashPolynomial) {
    Polynomial p1(4, 17);
    std::vector<uint64_t> coeffs1 = {1, 2, 3, 4};
    p1.setCoefficients(coeffs1);

    Polynomial p2(4, 17);
    std::vector<uint64_t> coeffs2 = {1, 2, 3, 5};
    p2.setCoefficients(coeffs2);

    auto hash1 = SHA256::polyToHash(p1);
    auto hash2 = SHA256::polyToHash(p2);

    EXPECT_EQ(SHA256::polyToHash(p1), hash1);
    EXPECT_NE(hash1, hash2);
    EXPECT_EQ(hash1.size(), SHA256_DIGEST_LENGTH);
    EXPECT_EQ(hash2.size(), SHA256_DIGEST_LENGTH);
}

TEST(SHA256Test, ConsistentHashes) {
    std::string msg = "test message";
    auto hash1 = SHA256::hash(msg);
    auto hash2 = SHA256::hash(msg);
    EXPECT_EQ(hash1, hash2);
}
