#ifndef RLWE_H
#define RLWE_H

#include <cmath>
#include <polynomial.h>
#include <vector>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <logging.h>

// Security level enumeration based on NIST standards
enum class SecurityLevel {
    // INSECURE - Only for testing/development
    TEST_TINY,       // n=8,   q=7681,  σ=3.0  - ~4 bits security  - INSECURE
    TEST_SMALL,      // n=32,  q=7681,  σ=3.0  - ~16 bits security - INSECURE
    
    // SECURE - Production parameters based on NIST standards
    KYBER512,        // n=256, q=3329,  σ=1.6  - ~128 bits classical, ~64 bits quantum
    MODERATE,        // n=512, q=12289, σ=3.2  - ~192 bits classical, ~96 bits quantum
    HIGH,            // n=1024,q=16384, σ=3.2  - ~256 bits classical, ~128 bits quantum
};

// Parameter structure
struct RLWEParams {
    size_t n;           // Ring dimension
    uint64_t q;         // Modulus
    double sigma;       // Gaussian standard deviation
    const char* name;   // Parameter set name
    int classical_bits; // Estimated classical security in bits
    int quantum_bits;   // Estimated quantum security in bits
    bool is_secure;     // Whether parameters are cryptographically secure
};

class RLWESignature {
public:
    // Constructor with explicit parameters
    RLWESignature(size_t n, uint64_t q, double sigma = 0.0);
    
    // Constructor with security level (RECOMMENDED)
    // Defaults to KYBER512 (NIST standard, secure)
    explicit RLWESignature(SecurityLevel level = SecurityLevel::KYBER512);
    
    void generateKeys();
    Polynomial blindSign(const Polynomial& blindedMessage);
    bool verify(const std::vector<uint8_t>& secret, 
               const Polynomial& signature);

    std::pair<Polynomial, Polynomial> getPublicKey() const {
        return std::make_pair(a, b);
    }

    Polynomial hashToPolynomial(const std::vector<uint8_t>& message);
    std::pair<Polynomial, Polynomial> computeBlindedMessage(const std::vector<uint8_t>& secret);
    Polynomial computeSignature(const Polynomial& blindSignature, const Polynomial& blindingFactor, const Polynomial& publicKey);
    
    // Get current parameters
    RLWEParams getParameters() const;
    
    // Get predefined parameter sets
    static RLWEParams getParameterSet(SecurityLevel level);

private:
    size_t ring_dim_n;
    uint64_t modulus;
    double gaussian_stddev;
    
    // Public key components
    Polynomial a;  // Random polynomial
    Polynomial b;  // a*s + e
    
    // Private key
    Polynomial s;  // Secret key
    
    // Helper functions
    uint64_t getRandomUint64();
    double getRandomDouble();
    Polynomial sampleUniform();
    Polynomial sampleGaussian(double stddev);
    Polynomial messageToPolynomial(const std::vector<uint8_t>& message);
    void validateSecurityParameters();
    
    // Verification parameters
    static constexpr double LARGE_THRESHOLD_DIVISOR = 4.0;   // For values near q/2
    static constexpr size_t MIN_DIFFERENT_COEFFS = 1;       // Even a single significant difference is meaningful

    // Logging helper
    void logMessageBytes(const std::string& prefix, const std::vector<uint8_t>& message) {
        std::stringstream ss;
        ss << prefix << " bytes: [";
        for (size_t i = 0; i < message.size(); ++i) {
            if (i > 0) ss << ", ";
            ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') 
               << static_cast<int>(message[i]);
        }
        ss << "]";
        Logger::log(ss.str());
    }
};

#endif // RLWE_H
