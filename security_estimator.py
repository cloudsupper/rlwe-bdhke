#!/usr/bin/env python3
"""
RLWE Security Parameter Estimator

This script provides security estimates for the RLWE blind signature implementation.
It uses simplified heuristics based on the LWE/RLWE security estimation literature.

For precise estimates, use the lattice-estimator: https://github.com/malb/lattice-estimator
"""

import math
import sys

def log2(x):
    """Safe logarithm base 2"""
    if x <= 0:
        return float('-inf')
    return math.log2(x)

def estimate_rlwe_security(n, log_q, sigma):
    """
    Estimate RLWE security using simplified formulas based on:
    - Albrecht et al. "On the complexity of the BKW algorithm on LWE"
    - NIST PQC security analysis
    
    This is a SIMPLIFIED estimate. For production use, always verify with lattice-estimator.
    
    Args:
        n: Ring dimension (polynomial degree)
        log_q: log2 of modulus q
        sigma: Standard deviation of error distribution
    
    Returns:
        dict: Security estimates for various attack types
    """
    q = 2 ** log_q
    alpha = sigma / q
    
    # LWE/RLWE security estimation based on Core-SVP hardness
    # Using simplified formulas from:
    # - Albrecht et al. "Estimate all the {LWE, NTRU} schemes!"
    # - NIST PQC Round 3 security analysis
    
    # Hermite delta for BKZ
    def delta_BKZ(beta):
        """Root Hermite factor achievable with BKZ-beta"""
        if beta <= 50:
            # Small blocksizes - use empirical formula
            return ((beta / (2 * math.pi * math.e)) * (math.pi * beta) ** (1.0/beta)) ** (1.0/(2*(beta-1)))
        else:
            # Chen-Nguyen estimate for large blocksizes
            return ((beta / (2 * math.pi * math.e)) * (math.pi * beta) ** (1.0/beta)) ** (1.0/(2*beta))
    
    # Core-SVP hardness approach
    # We estimate the blocksize beta needed to achieve a target root hermite factor
    # For RLWE with dim n, modulus q, and error sigma:
    # - Lattice dimension: d = 2n (for primal attack)
    # - Required advantage: delta^d < q/sigma
    
    sigma_safe = max(sigma, 1.0)  # Avoid division by zero
    
    # Target root hermite factor
    # delta^(2n) ≈ sigma/q (for successful attack)
    target_delta = (sigma_safe / q) ** (1.0 / (2 * n))
    
    # Find required blocksize via binary search
    beta_min = 50
    beta_max = 2 * n + 1000
    
    for beta_try in range(beta_min, beta_max):
        if delta_BKZ(beta_try) <= target_delta:
            beta = beta_try
            break
    else:
        beta = beta_max
    
    # Clamp beta to reasonable range
    beta = max(beta, 2)
    beta = min(beta, beta_max)
    
    # Core-SVP hardness (conservative estimate)
    # Cost ≈ 2^(0.292 * beta) for enumeration-based BKZ
    # Cost ≈ 2^(0.2075 * beta) for sieving-based BKZ
    classical_bits_enum = 0.292 * beta
    classical_bits_sieve = 0.2075 * beta
    classical_bits = min(classical_bits_enum, classical_bits_sieve)
    
    # Quantum security (Grover speedup): roughly sqrt of classical
    quantum_bits = classical_bits / 2
    
    # Primal attack estimate
    # Dimension of the lattice: m + n
    # Typical m ≈ n for RLWE
    lattice_dim = 2 * n
    
    # Dual attack estimate (simplified)
    # Usually similar to primal for RLWE
    
    # Algebraic attack (specific to Ring-LWE)
    # Only relevant for small n with special structure
    algebraic_bits = float('inf')
    if n < 128:
        # Polynomial system solving
        # Very rough estimate: exponential in n
        algebraic_bits = max(0, n * 0.5)
    
    return {
        'parameters': {
            'n': n,
            'q': int(q),
            'log_q': log_q,
            'sigma': sigma,
            'alpha': alpha
        },
        'bkz_blocksize': beta,
        'classical_security_bits': max(0, classical_bits),
        'quantum_security_bits': max(0, quantum_bits),
        'algebraic_security_bits': algebraic_bits,
        'effective_classical_bits': max(0, min(classical_bits, algebraic_bits)),
        'effective_quantum_bits': max(0, quantum_bits),
    }

def print_security_report(params):
    """Print a formatted security report"""
    print("\n" + "="*70)
    print("RLWE SECURITY ESTIMATION REPORT")
    print("="*70)
    
    p = params['parameters']
    print(f"\nParameters:")
    print(f"  Ring dimension (n):        {p['n']}")
    print(f"  Modulus (q):               {p['q']} (≈ 2^{p['log_q']:.2f})")
    print(f"  Error std dev (σ):         {p['sigma']:.2f}")
    print(f"  Noise ratio (α = σ/q):     {p['alpha']:.6e}")
    
    print(f"\nAttack Analysis:")
    print(f"  BKZ blocksize required:    {params['bkz_blocksize']}")
    
    print(f"\nSecurity Estimates:")
    print(f"  Classical security:        {params['classical_security_bits']:.1f} bits")
    print(f"  Quantum security:          {params['quantum_security_bits']:.1f} bits")
    
    if params['algebraic_security_bits'] < float('inf'):
        print(f"  Algebraic attack:          {params['algebraic_security_bits']:.1f} bits")
    
    print(f"\nEffective Security Level:")
    print(f"  Classical:                 {params['effective_classical_bits']:.1f} bits")
    print(f"  Quantum:                   {params['effective_quantum_bits']:.1f} bits")
    
    # Security level classification
    classical_sec = params['effective_classical_bits']
    print(f"\nSecurity Classification:")
    if classical_sec < 80:
        print(f"  ⚠️  INSECURE - Vulnerable to practical attacks")
    elif classical_sec < 100:
        print(f"  ⚠️  WEAK - Not recommended for production")
    elif classical_sec < 128:
        print(f"  🟡 MODERATE - May be acceptable for some applications")
    elif classical_sec < 192:
        print(f"  🟢 GOOD - Suitable for most applications")
    elif classical_sec < 256:
        print(f"  🟢 STRONG - High security")
    else:
        print(f"  🟢 VERY STRONG - Excellent security")
    
    print("="*70)

def main():
    print("RLWE Blind Signature - Security Parameter Analysis")
    print("\nNote: These are SIMPLIFIED estimates. For production systems,")
    print("use the lattice-estimator: https://github.com/malb/lattice-estimator\n")
    
    # Current implementation parameters
    print("\n" + "#"*70)
    print("# CURRENT IMPLEMENTATION PARAMETERS (FROM CODE)")
    print("#"*70)
    
    current_small = estimate_rlwe_security(n=8, log_q=log2(7681), sigma=3.0)
    print("\n1. Small Test Parameters (n=8):")
    print_security_report(current_small)
    
    current_large = estimate_rlwe_security(n=32, log_q=log2(7681), sigma=3.0)
    print("\n2. Large Test Parameters (n=32):")
    print_security_report(current_large)
    
    # Recommended parameters
    print("\n" + "#"*70)
    print("# RECOMMENDED SECURE PARAMETERS")
    print("#"*70)
    
    # Low security (for reference)
    low_sec = estimate_rlwe_security(n=256, log_q=log2(7681), sigma=3.0)
    print("\n3. Minimal Secure Parameters (n=256, q=7681):")
    print_security_report(low_sec)
    
    # Medium security - Similar to Kyber512
    medium_sec = estimate_rlwe_security(n=256, log_q=log2(3329), sigma=1.6)
    print("\n4. Kyber-like Parameters (n=256, q=3329, σ=1.6):")
    print_security_report(medium_sec)
    
    # Good security
    good_sec = estimate_rlwe_security(n=512, log_q=log2(12289), sigma=3.2)
    print("\n5. Recommended Moderate (n=512, q=12289, σ=3.2):")
    print_security_report(good_sec)
    
    # High security
    high_sec = estimate_rlwe_security(n=1024, log_q=14, sigma=3.2)
    print("\n6. Recommended High (n=1024, q≈2^14, σ=3.2):")
    print_security_report(high_sec)
    
    # Very high security
    very_high_sec = estimate_rlwe_security(n=2048, log_q=log2(1073479681), sigma=3.2)
    print("\n7. Recommended Very High (n=2048, q≈2^30, σ=3.2):")
    print_security_report(very_high_sec)
    
    # Summary comparison
    print("\n" + "#"*70)
    print("# SUMMARY COMPARISON")
    print("#"*70)
    print("\n{:<30} {:<10} {:<12} {:<15} {:<15}".format(
        "Configuration", "n", "q", "Classical", "Quantum"))
    print("-" * 80)
    
    configs = [
        ("Current Small (n=8)", current_small),
        ("Current Large (n=32)", current_large),
        ("Minimal (n=256)", low_sec),
        ("Kyber-like (n=256)", medium_sec),
        ("Moderate (n=512)", good_sec),
        ("High (n=1024)", high_sec),
        ("Very High (n=2048)", very_high_sec),
    ]
    
    for name, params in configs:
        p = params['parameters']
        print("{:<30} {:<10} {:<12} {:<15.1f} {:<15.1f}".format(
            name,
            p['n'],
            str(p['q']),
            params['effective_classical_bits'],
            params['effective_quantum_bits']
        ))
    
    print("\n" + "="*70)
    print("RECOMMENDATIONS:")
    print("="*70)
    print("\n1. IMMEDIATE: Current parameters provide ~0-10 bits of security")
    print("   ⚠️  DO NOT USE IN PRODUCTION")
    print("\n2. MINIMUM: Use n≥256 with appropriate q and σ for any real use")
    print("\n3. RECOMMENDED: Use n≥512 for 100+ bit classical security")
    print("\n4. For blind signatures similar to Cashu:")
    print("   - Use n=512, q=12289, σ=3.2 (moderate security)")
    print("   - Or n=1024 for higher security")
    print("\n5. Always validate parameters with lattice-estimator before deployment")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
