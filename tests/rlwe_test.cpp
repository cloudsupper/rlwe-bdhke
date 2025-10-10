#include <gtest/gtest.h>
#include "rlwe.h"
#include "logging.h"
#include <iostream>

class RLWETest : public ::testing::Test {
protected:
    void SetUp() override {
        // Use TEST_TINY for fast unit tests
        rlwe = std::make_unique<RLWESignature>(SecurityLevel::TEST_TINY);
        Logger::setOutputStream(std::cout);
        Logger::enable_logging = true;
        Logger::log("Test setup with TEST_TINY parameters (INSECURE - for testing only)");
    }
    
    void TearDown() override {
        Logger::log("Test complete\n");
    }
    
    std::unique_ptr<RLWESignature> rlwe;
};

// New test class for larger polynomial degree
class RLWELargeTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Use TEST_SMALL for larger but still fast tests
        rlwe = std::make_unique<RLWESignature>(SecurityLevel::TEST_SMALL);
        Logger::setOutputStream(std::cout);
        Logger::enable_logging = true;
        Logger::log("Large polynomial test setup with TEST_SMALL parameters (INSECURE - for testing only)");
    }
    
    void TearDown() override {
        Logger::log("Large polynomial test complete\n");
    }
    
    std::unique_ptr<RLWESignature> rlwe;
};

// New test class for NIST-standard secure parameters
class RLWESecureTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Use KYBER512 for secure parameters
        rlwe = std::make_unique<RLWESignature>(SecurityLevel::KYBER512);
        Logger::setOutputStream(std::cout);
        Logger::enable_logging = true;
        Logger::log("Secure parameter test setup with KYBER512 (NIST Standard)");
    }
    
    void TearDown() override {
        Logger::log("Secure parameter test complete\n");
    }
    
    std::unique_ptr<RLWESignature> rlwe;
};

TEST_F(RLWETest, KeyGeneration) {
    Logger::log("\n=== Starting Key Generation Test ===");
    
    ASSERT_NO_THROW({
        Logger::log("Generating keys...");
        rlwe->generateKeys();
        Logger::log("Keys generated successfully");
    });
    
    auto [a, b] = rlwe->getPublicKey();
    auto params = rlwe->getParameters();
    
    Logger::log("Public key a: " + a.toString());
    Logger::log("Public key b: " + b.toString());
    
    EXPECT_EQ(a.degree(), params.n) << "Public key 'a' has wrong degree";
    EXPECT_EQ(b.degree(), params.n) << "Public key 'b' has wrong degree";
    EXPECT_EQ(a.getModulus(), params.q) << "Public key 'a' has wrong modulus";
    EXPECT_EQ(b.getModulus(), params.q) << "Public key 'b' has wrong modulus";
}

TEST_F(RLWETest, CompleteBlindSignatureFlow) {
    Logger::log("\n=== Starting Complete Blind Signature Flow Test ===");
    
    // 1. Server setup
    Logger::log("\n1. Server Setup");
    rlwe->generateKeys();
    // a is the "generator" and b is the publickey
    auto [a, b] = rlwe->getPublicKey();
    Logger::log("Server public key a: " + a.toString());
    Logger::log("Server public key b: " + b.toString());
    
    // 2. Client: Create secret and blind it
    Logger::log("\n2. Client: Blinding Process");
    std::vector<uint8_t> secret = {0x12, 0x34};
    Logger::log("Client secret: 0x1234");
    
    Logger::log("Computing blinded message...");
    auto [blindedMessage, blindingFactor] = rlwe->computeBlindedMessage(secret);
    Logger::log("Blinded message: " + blindedMessage.toString());
    Logger::log("Blinding factor: " + blindingFactor.toString());
    
    // 3. Server: Generate blind signature
    Logger::log("\n3. Server: Blind Signing");
    Logger::log("Server generating blind signature...");
    Polynomial blindSignature = rlwe->blindSign(blindedMessage);
    Logger::log("Blind signature: " + blindSignature.toString());
    
    // 4. Client: Unblind the signature
    Logger::log("\n4. Client: Unblinding");
    Logger::log("Client computing final signature...");
    Polynomial signature = rlwe->computeSignature(blindSignature, blindingFactor, b);
    Logger::log("Final signature: " + signature.toString());
    
    // 5. Server: Verify the signature against a secret
    Logger::log("\n5. Server: Verification");
    Logger::log("Server verifying signature with original secret...");
    bool verified = rlwe->verify(secret, signature);
    Logger::log("Verification result: " + std::string(verified ? "SUCCESS" : "FAILED"));
    EXPECT_TRUE(verified) << "Valid signature failed to verify";
    
    // 6. Verify fails with wrong secret
    Logger::log("\n6. Testing Wrong Secret");
    std::vector<uint8_t> wrong_secret = {0x12, 0x35};
    Logger::log("Attempting verification with wrong secret: 0x1235");
    bool wrong_verify = rlwe->verify(wrong_secret, signature);
    Logger::log("Wrong secret verification result: " + std::string(wrong_verify ? "INCORRECTLY SUCCEEDED" : "CORRECTLY FAILED"));
    EXPECT_FALSE(wrong_verify) << "Signature incorrectly verified with wrong secret";
}

TEST_F(RLWELargeTest, CompleteBlindSignatureFlowLarge) {
    Logger::log("\n=== Starting Complete Blind Signature Flow Test with n=32 ===");
    
    // 1. Server setup
    Logger::log("\n1. Server Setup (n=32)");
    rlwe->generateKeys();
    auto [a, b] = rlwe->getPublicKey();
    Logger::log("Server public key a: " + a.toString());
    Logger::log("Server public key b: " + b.toString());
    
    // 2. Client: Create secret and blind it
    Logger::log("\n2. Client: Blinding Process");
    // Using a larger secret for the larger polynomial
    std::vector<uint8_t> secret = {0x12, 0x34, 0x56, 0x78};
    Logger::log("Client secret: 0x12345678");
    
    Logger::log("Computing blinded message...");
    auto [blindedMessage, blindingFactor] = rlwe->computeBlindedMessage(secret);
    Logger::log("Blinded message: " + blindedMessage.toString());
    Logger::log("Blinding factor: " + blindingFactor.toString());
    
    // 3. Server: Generate blind signature
    Logger::log("\n3. Server: Blind Signing");
    Logger::log("Server generating blind signature...");
    Polynomial blindSignature = rlwe->blindSign(blindedMessage);
    Logger::log("Blind signature: " + blindSignature.toString());
    
    // 4. Client: Unblind the signature
    Logger::log("\n4. Client: Unblinding");
    Logger::log("Client computing final signature...");
    Polynomial signature = rlwe->computeSignature(blindSignature, blindingFactor, b);
    Logger::log("Final signature: " + signature.toString());
    
    // 5. Server: Verify the signature against a secret
    Logger::log("\n5. Server: Verification");
    Logger::log("Server verifying signature with original secret...");
    bool verified = rlwe->verify(secret, signature);
    Logger::log("Verification result: " + std::string(verified ? "SUCCESS" : "FAILED"));
    EXPECT_TRUE(verified) << "Valid signature failed to verify";
    
    // 6. Verify fails with wrong secret
    Logger::log("\n6. Testing Wrong Secret");
    std::vector<uint8_t> wrong_secret = {0x12, 0x34, 0x56, 0x79};  // Changed last byte
    Logger::log("Attempting verification with wrong secret: 0x12345679");
    bool wrong_verify = rlwe->verify(wrong_secret, signature);
    Logger::log("Wrong secret verification result: " + std::string(wrong_verify ? "INCORRECTLY SUCCEEDED" : "CORRECTLY FAILED"));
    EXPECT_FALSE(wrong_verify) << "Signature incorrectly verified with wrong secret";
    
    // 7. Additional verification for polynomial degree
    auto params = rlwe->getParameters();
    Logger::log("\n7. Verifying polynomial degrees");
    EXPECT_EQ(blindedMessage.degree(), params.n) << "Blinded message has wrong degree";
    EXPECT_EQ(blindSignature.degree(), params.n) << "Blind signature has wrong degree";
    EXPECT_EQ(signature.degree(), params.n) << "Final signature has wrong degree";
}

TEST_F(RLWETest, HashToPolynomial) {
    Logger::log("\n=== Starting Hash To Polynomial Test ===");
    
    auto params = rlwe->getParameters();
    
    // Test with a simple message
    std::vector<uint8_t> message1 = {0x12, 0x34};
    Logger::log("Testing with message: 0x1234");
    
    Logger::log("Computing first hash polynomial...");
    auto poly1 = rlwe->hashToPolynomial(message1);
    Logger::log("Result polynomial: " + poly1.toString());
    
    // Check polynomial properties
    Logger::log("\nChecking polynomial properties:");
    Logger::log("Degree: " + std::to_string(poly1.degree()) + " (expected: " + std::to_string(params.n) + ")");
    Logger::log("Modulus: " + std::to_string(poly1.getModulus()) + " (expected: " + std::to_string(params.q) + ")");
    
    EXPECT_EQ(poly1.degree(), params.n) << "Hash polynomial has wrong degree";
    EXPECT_EQ(poly1.getModulus(), params.q) << "Hash polynomial has wrong modulus";
    
    // Check coefficients are binary (0 or q/2)
    Logger::log("\nChecking coefficient values:");
    const auto& coeffs1 = poly1.getCoeffs();
    uint64_t q_half = params.q / 2;
    for (size_t i = 0; i < coeffs1.size(); i++) {
        Logger::log("Coefficient " + std::to_string(i) + ": " + std::to_string(coeffs1[i]));
        EXPECT_TRUE(coeffs1[i] == 0 || coeffs1[i] == q_half) 
            << "Coefficient " << i << " is neither 0 nor q/2";
    }
    
    // Test deterministic property
    Logger::log("\nTesting deterministic property");
    Logger::log("Computing hash polynomial again with same input...");
    auto poly1_repeat = rlwe->hashToPolynomial(message1);
    Logger::log("Repeat polynomial: " + poly1_repeat.toString());
    EXPECT_EQ(poly1.getCoeffs(), poly1_repeat.getCoeffs()) 
        << "Hash function not deterministic";
    
    // Test different input
    Logger::log("\nTesting with different input");
    std::vector<uint8_t> message2 = {0x12, 0x35};
    Logger::log("Computing hash polynomial with message: 0x1235");
    auto poly2 = rlwe->hashToPolynomial(message2);
    Logger::log("Different input polynomial: " + poly2.toString());
    EXPECT_NE(poly1.getCoeffs(), poly2.getCoeffs()) 
        << "Different inputs produced same hash polynomial";
}

TEST_F(RLWETest, VerifyFailsOnTamperedSecret) {
    Logger::log("\n=== Starting Tampered Secret Test ===");
    
    // Setup
    Logger::log("Generating keys and computing valid signature...");
    rlwe->generateKeys();
    std::vector<uint8_t> secret = {0x12, 0x34};
    Logger::log("Original secret: 0x1234");
    
    // Get valid signature
    auto [blindedMessage, blindingFactor] = rlwe->computeBlindedMessage(secret);
    Logger::log("Blinded message: " + blindedMessage.toString());
    
    Polynomial blindSignature = rlwe->blindSign(blindedMessage);
    Logger::log("Blind signature: " + blindSignature.toString());
    
    Polynomial signature = rlwe->computeSignature(blindSignature, blindingFactor, rlwe->getPublicKey().second);
    Logger::log("Final signature: " + signature.toString());
    
    // Verify with tampered secret
    std::vector<uint8_t> tampered_secret = {0x12, 0x35};
    Logger::log("\nAttempting verification with tampered secret: 0x1235");
    bool verified = rlwe->verify(tampered_secret, signature);
    Logger::log("Tampered verification result: " + std::string(verified ? "INCORRECTLY SUCCEEDED" : "CORRECTLY FAILED"));
    EXPECT_FALSE(verified) << "Signature incorrectly verified with tampered secret";
}

TEST_F(RLWETest, VerifyFailsOnForgedSignature) {
    Logger::log("\n=== Starting Forged Signature Test ===");
    
    auto params = rlwe->getParameters();
    
    // Setup
    Logger::log("Generating keys...");
    rlwe->generateKeys();
    std::vector<uint8_t> secret = {0x12, 0x34};
    Logger::log("Secret: 0x1234");
    
    // Create forged signature
    Logger::log("\nCreating forged signature (all coefficients = 1)");
    Polynomial forged_sig(params.n, params.q);
    std::vector<uint64_t> forged_coeffs(params.n, 1);
    forged_sig.setCoefficients(forged_coeffs);
    Logger::log("Forged signature: " + forged_sig.toString());
    
    // Verify should fail
    Logger::log("\nAttempting verification with forged signature...");
    bool verified = rlwe->verify(secret, forged_sig);
    Logger::log("Forged signature verification result: " + std::string(verified ? "INCORRECTLY SUCCEEDED" : "CORRECTLY FAILED"));
    EXPECT_FALSE(verified) << "Forged signature incorrectly verified";
}

TEST_F(RLWETest, VerifyFailsOnZeroSignature) {
    Logger::log("\n=== Starting Zero Signature Test ===");
    
    auto params = rlwe->getParameters();
    
    // Setup
    Logger::log("Generating keys...");
    rlwe->generateKeys();
    std::vector<uint8_t> secret = {0x12, 0x34};
    Logger::log("Secret: 0x1234");
    
    // Create zero signature
    Logger::log("\nCreating zero signature (all coefficients = 0)");
    Polynomial zero_sig(params.n, params.q);
    std::vector<uint64_t> zero_coeffs(params.n, 0);
    zero_sig.setCoefficients(zero_coeffs);
    Logger::log("Zero signature: " + zero_sig.toString());
    
    // Verify should fail
    Logger::log("\nAttempting verification with zero signature...");
    bool verified = rlwe->verify(secret, zero_sig);
    Logger::log("Zero signature verification result: " + std::string(verified ? "INCORRECTLY SUCCEEDED" : "CORRECTLY FAILED"));
    EXPECT_FALSE(verified) << "Zero signature incorrectly verified";
}

// New test with secure KYBER512 parameters
TEST_F(RLWESecureTest, CompleteBlindSignatureFlowSecure) {
    Logger::log("\n=== Starting Complete Blind Signature Flow with KYBER512 ===");
    
    // 1. Server setup
    Logger::log("\n1. Server Setup (KYBER512 - NIST Standard)");
    rlwe->generateKeys();
    auto [a, b] = rlwe->getPublicKey();
    
    // 2. Client: Create secret and blind it
    Logger::log("\n2. Client: Blinding Process");
    std::vector<uint8_t> secret = {0xDE, 0xAD, 0xBE, 0xEF};
    Logger::log("Client secret: 0xDEADBEEF");
    
    Logger::log("Computing blinded message...");
    auto [blindedMessage, blindingFactor] = rlwe->computeBlindedMessage(secret);
    
    // 3. Server: Generate blind signature
    Logger::log("\n3. Server: Blind Signing");
    Polynomial blindSignature = rlwe->blindSign(blindedMessage);
    
    // 4. Client: Unblind the signature
    Logger::log("\n4. Client: Unblinding");
    Polynomial signature = rlwe->computeSignature(blindSignature, blindingFactor, b);
    
    // 5. Server: Verify the signature against a secret
    Logger::log("\n5. Server: Verification");
    bool verified = rlwe->verify(secret, signature);
    Logger::log("Verification result: " + std::string(verified ? "SUCCESS" : "FAILED"));
    EXPECT_TRUE(verified) << "Valid signature failed to verify with KYBER512 parameters";
    
    // 6. Verify fails with wrong secret
    Logger::log("\n6. Testing Wrong Secret");
    std::vector<uint8_t> wrong_secret = {0xDE, 0xAD, 0xBE, 0xEE};
    bool wrong_verify = rlwe->verify(wrong_secret, signature);
    EXPECT_FALSE(wrong_verify) << "Signature incorrectly verified with wrong secret";
}
