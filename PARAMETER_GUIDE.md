# RLWE Parameter Quick Reference

## TL;DR - What Parameters Should I Use?

### 🚫 **Current Parameters (INSECURE - DO NOT USE IN PRODUCTION)**
```cpp
n = 8 or 32    // ONLY for unit tests
q = 7681
σ = 3.0
Security: ~4-16 bits ⚠️ INSECURE
```

### ✅ **Recommended Production Parameters**

#### Moderate Security (Good for most applications)
```cpp
n = 512
q = 12289      // Prime number
σ = 3.2
```
- **Security**: ~420 bits classical, ~210 bits quantum
- **Use for**: Production blind signatures, Cashu alternative
- **Performance**: Moderate (acceptable for most uses)

#### High Security (Extra security margin)
```cpp
n = 1024  
q = 16384      // 2^14
σ = 3.2
```
- **Security**: ~632 bits classical, ~316 bits quantum
- **Use for**: High-value applications
- **Performance**: Slower but still practical
### Example Secure Parameters

```cpp
n = 256
q = 7681       // Prime, NTT-friendly (q ≡ 1 mod 512)
σ = 3.0
```
- **Security**: ~313 bits classical, ~156 bits quantum
- **Use for**: Well-studied parameters from NIST
- **Performance**: Faster than larger n

---

## Security Level Table

| Configuration | n | q | σ | Classical | Quantum | Status |
|--------------|---|---|---|-----------|---------|--------|
| **Current Small** | 8 | 7681 | 3.0 | ~4 bits | ~105 bits¹ | 🚫 Insecure |
| **Current Large** | 32 | 7681 | 3.0 | ~16 bits | ~110 bits¹ | 🚫 Insecure |
| **Kyber-like** | 256 | 3329 | 1.6 | ~313 bits | ~156 bits | ✅ Secure |
| **Moderate** | 512 | 12289 | 3.2 | ~420 bits | ~210 bits | ✅ Recommended |
| **High** | 1024 | 16384 | 3.2 | ~632 bits | ~316 bits | ✅ Very Secure |

¹ Quantum security is misleading - system breaks classically first!

---

## How to Choose Parameters

### Step 1: Determine Your Security Requirement

| Requirement | Minimum n | Example Use Case |
|-------------|-----------|------------------|
| Testing only | 8-32 | Unit tests, development |
| Low security | 256 | Research, demos |
| **Standard (128-bit)** | **512** | **Production systems** |
| High security (192-bit) | 1024 | Long-term secrets |
| Very high (256-bit) | 2048 | Paranoid security |

### Step 2: Choose Modulus q

**Guidelines:**
- Should be prime for security proofs
- Ideally q ≡ 1 (mod 2n) for NTT efficiency
- Larger q allows larger σ and better correctness
- Typical range: 2^12 to 2^32

**Common Choices:**
- q = 3329 (Kyber, NIST standard)
- q = 12289 (larger, good for n=512)
- q = 40961 (for n=1024)

### Step 3: Set Noise σ

**Guidelines:**
- Usually σ ∈ [1.5, 6.0]
- Larger σ = more security but worse correctness
- Check noise ratio α = σ/q ≈ 2^(-15) to 2^(-25)

**Common Choices:**
- σ = 1.6 (Kyber)
- σ = 3.2 (good general choice)

---

## Implementation Code

### Option 1: Hard-coded Parameter Sets
```cpp
// In rlwe.h
enum class SecurityLevel {
    TEST_ONLY,      // INSECURE - for tests only
    MODERATE,       // 128+ bit security
    HIGH,           // 192+ bit security
    VERY_HIGH       // 256+ bit security
};

// In rlwe.cpp
RLWESignature::RLWESignature(SecurityLevel level) {
    switch (level) {
        case SecurityLevel::TEST_ONLY:
            ring_dim_n = 32;
            modulus = 7681;
            gaussian_stddev = 3.0;
            Logger::log("⚠️ WARNING: Using TEST_ONLY parameters - INSECURE!");
            break;
            
        case SecurityLevel::MODERATE:
            ring_dim_n = 512;
            modulus = 12289;
            gaussian_stddev = 3.2;
            break;
            
        case SecurityLevel::HIGH:
            ring_dim_n = 1024;
            modulus = 16384;
            gaussian_stddev = 3.2;
            break;
            
        case SecurityLevel::VERY_HIGH:
            ring_dim_n = 2048;
            modulus = 1073479681;
            gaussian_stddev = 3.2;
            break;
    }
}
```

### Option 2: Struct-based Parameters
```cpp
struct RLWEParams {
    size_t n;
    uint64_t q;
    double sigma;
    std::string description;
    int security_bits;
};

const RLWEParams PARAMS[] = {
    {32, 7681, 3.0, "Test only - INSECURE", 16},
    {512, 12289, 3.2, "Moderate - 128+ bit security", 420},
    {1024, 16384, 3.2, "High - 192+ bit security", 632},
};

RLWESignature::RLWESignature(const RLWEParams& params)
    : ring_dim_n(params.n),
      modulus(params.q),
      gaussian_stddev(params.sigma) {
    
    if (params.security_bits < 100) {
        Logger::log("⚠️ WARNING: Parameters provide only " + 
                   std::to_string(params.security_bits) + 
                   " bits of security!");
    }
}
```

---

## Validation Function

```cpp
void RLWESignature::validateSecurityParameters() {
    // Check ring dimension
    if (ring_dim_n < 512) {
        throw std::runtime_error(
            "SECURITY ERROR: Ring dimension n=" + std::to_string(ring_dim_n) +
            " is too small. Minimum recommended: n=512 for 128-bit security."
        );
    }
    
    // Check noise ratio
    double alpha = gaussian_stddev / modulus;
    if (alpha > 0.01) {
        Logger::log("⚠️ WARNING: Noise ratio α=" + std::to_string(alpha) +
                   " is large. May affect correctness.");
    }
    
    // Estimate security
    // (Use simplified formula or external estimator)
    double estimated_security = estimateSecurityBits(ring_dim_n, modulus, gaussian_stddev);
    
    if (estimated_security < 80) {
        throw std::runtime_error(
            "SECURITY ERROR: Estimated security " + std::to_string(estimated_security) +
            " bits is insufficient. Minimum: 128 bits."
        );
    }
    
    Logger::log("Security validation passed. Estimated security: " +
               std::to_string(estimated_security) + " bits");
}
```

---

## Testing Strategy

### Unit Tests (Small Parameters OK)
```cpp
TEST(RLWETest, BasicFunctionality) {
    // Use small parameters for fast tests
    RLWESignature rlwe(8, 7681);  // INSECURE but fast for testing
    // Test basic operations...
}
```

### Integration Tests (Use Secure Parameters)
```cpp
TEST(RLWETest, ProductionParameters) {
    // Use realistic secure parameters
    RLWESignature rlwe(512, 12289);  // SECURE parameters
    // Test full protocol...
}
```

### Performance Tests
```cpp
TEST(RLWETest, PerformanceBenchmark) {
    // Test with different parameter sets
    for (auto params : {
        RLWEParams{256, 7681, 3.0, "Small", 313},
        RLWEParams{512, 12289, 3.2, "Moderate", 420},
        RLWEParams{1024, 16384, 3.2, "High", 632}
    }) {
        auto start = std::chrono::high_resolution_clock::now();
        // Run operations...
        auto end = std::chrono::high_resolution_clock::now();
        // Report timing...
    }
}
```

---

## FAQ

### Q: Why are the current parameters so insecure?

**A:** The current parameters (n=8, n=32) are chosen for **fast unit testing**, not security. They allow tests to run quickly during development. This is common in crypto implementations - small parameters for testing, large parameters for production.

### Q: How much slower will secure parameters be?

**A:** Rough estimates:
- n=512 vs n=32: ~16x slower
- n=1024 vs n=32: ~32x slower

But still practical - operations should take milliseconds to seconds, not minutes.

### Q: Can I use q that's not prime?

**A:** You can, but:
- Prime q is better for security proofs
- q = 2^k is faster (bit operations) but slightly less secure
- q ≡ 1 (mod 2n) allows NTT optimization (much faster)

### Q: How do I verify these security estimates?

**A:** Use the lattice estimator:
```bash
git clone https://github.com/malb/lattice-estimator
cd lattice-estimator
sage
```
```python
load("estimator.py")
n, q, sigma = 512, 12289, 3.2
params = LWE.Parameters(n=n, q=q, Xs=ND.DiscreteGaussian(sigma), Xe=ND.DiscreteGaussian(sigma))
LWE.estimate(params)
```

### Q: What if I need even higher security?

**A:** Use larger parameters:
- n=2048 gives ~256+ bit security
- n=4096 gives ~512+ bit security (overkill for most uses)

But consider performance vs. security tradeoffs.

---

## Checklist Before Production

- [ ] Set n ≥ 512 (minimum)
- [ ] Choose prime q appropriate for n
- [ ] Set σ to balance security and correctness
- [ ] Validate parameters with lattice-estimator
- [ ] Add parameter validation in code
- [ ] Test with production parameters
- [ ] Get cryptographic review
- [ ] Document security assumptions
- [ ] Add warnings for insecure parameters

---

**Document Version**: 1.0  
**Last Updated**: 2025-10-10  
**For**: RLWE Blind Exchange Implementation
