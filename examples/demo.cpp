#include <rlwe.h>
#include <logging.h>
#include <iostream>
#include <iomanip>

int main() {
    Logger::enable_logging = false;
    
    std::cout << "\n";
    std::cout << "======================================================================\n";
    std::cout << "    RLWE Blind Signature Demo - NIST KYBER512 Parameters\n";
    std::cout << "======================================================================\n\n";
    
    std::cout << "Creating RLWE instance with KYBER512 parameters...\n";
    RLWESignature rlwe(SecurityLevel::KYBER512);
    
    auto params = rlwe.getParameters();
    std::cout << "  Ring dimension (n):     " << params.n << "\n";
    std::cout << "  Modulus (q):            " << params.q << "\n";
    std::cout << "  Gaussian σ:             " << params.sigma << "\n";
    std::cout << "  Classical security:     ~" << params.classical_bits << " bits\n";
    std::cout << "  Quantum security:       ~" << params.quantum_bits << " bits\n";
    std::cout << "  Security status:        " << (params.is_secure ? "✓ SECURE" : "⚠️  INSECURE") << "\n\n";
    
    std::cout << "Generating keys...\n";
    rlwe.generateKeys();
    auto [a, b] = rlwe.getPublicKey();
    std::cout << "  ✓ Keys generated successfully\n\n";
    
    std::cout << "CLIENT: Creating and blinding secret...\n";
    std::vector<uint8_t> secret = {0xDE, 0xAD, 0xBE, 0xEF};
    std::cout << "  Secret: 0xDEADBEEF\n";
    
    auto [blindedMessage, blindingFactor] = rlwe.computeBlindedMessage(secret);
    std::cout << "  ✓ Message blinded\n\n";
    
    std::cout << "SERVER: Generating blind signature...\n";
    Polynomial blindSignature = rlwe.blindSign(blindedMessage);
    std::cout << "  ✓ Blind signature generated\n\n";
    
    std::cout << "CLIENT: Unblinding signature...\n";
    Polynomial signature = rlwe.computeSignature(blindSignature, blindingFactor, b);
    std::cout << "  ✓ Signature unblinded\n\n";
    
    std::cout << "SERVER: Verifying signature...\n";
    bool verified = rlwe.verify(secret, signature);
    std::cout << "  " << (verified ? "✓" : "✗") << " Verification: " 
              << (verified ? "SUCCESS" : "FAILED") << "\n\n";
    
    std::cout << "SERVER: Testing with wrong secret...\n";
    std::vector<uint8_t> wrong_secret = {0xDE, 0xAD, 0xBE, 0xEE};
    std::cout << "  Wrong secret: 0xDEADBEEE\n";
    bool wrong_verified = rlwe.verify(wrong_secret, signature);
    std::cout << "  " << (wrong_verified ? "✗" : "✓") << " Verification: " 
              << (wrong_verified ? "INCORRECTLY SUCCEEDED" : "CORRECTLY FAILED") << "\n\n";
    
    std::cout << "======================================================================\n";
    std::cout << "  Demo completed successfully!\n";
    std::cout << "======================================================================\n\n";
    
    std::cout << "\n";
    std::cout << "======================================================================\n";
    std::cout << "    Available Security Levels\n";
    std::cout << "======================================================================\n\n";
    
    std::vector<SecurityLevel> levels = {
        SecurityLevel::TEST_TINY,
        SecurityLevel::TEST_SMALL,
        SecurityLevel::KYBER512,
        SecurityLevel::MODERATE,
        SecurityLevel::HIGH
    };
    
    std::cout << "Level             n      q       σ     Classical  Quantum   Status\n";
    std::cout << "----------------------------------------------------------------------\n";
    
    for (auto level : levels) {
        auto p = RLWESignature::getParameterSet(level);
        std::cout << std::left << std::setw(16) << p.name 
                  << std::right << std::setw(6) << p.n 
                  << std::setw(8) << p.q
                  << std::setw(7) << std::fixed << std::setprecision(1) << p.sigma
                  << std::setw(11) << p.classical_bits << " bits"
                  << std::setw(9) << p.quantum_bits << " bits  "
                  << (p.is_secure ? "✓" : "⚠️ ") << "\n";
    }
    
    std::cout << "\n⚠️  = INSECURE - Only for testing/development\n";
    std::cout << "✓  = SECURE - Suitable for production\n\n";
    
    std::cout << "======================================================================\n\n";
    
    return 0;
}
