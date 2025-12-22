#ifndef NTT_H
#define NTT_H

#include <cstdint>
#include <cstddef>
#include <vector>
#include <stdexcept>

#include <logging.h>
#include <polynomial.h>

/**
 * @brief Number Theoretic Transform for Z_q[x]/(x^n + 1).
 *
 * This implementation is "negacyclic aware": for supported parameter sets
 * where the modulus q satisfies q ≡ 1 (mod 2n), it uses **precomputed**
 * primitive 2n‑th roots of unity @f$\psi@f$ such that @f$\psi^n = -1
 * (mod q)@f$ and implements a length‑n NTT suitable for negacyclic
 * convolution modulo @f$x^n + 1@f$ **without padding to length 2n**.
 * For unsupported (n, q) combinations the constructor will throw.
 *
 * Internally we use the standard Cooley–Tukey radix‑2 NTT of length n with
 * an n‑th primitive root of unity @f$\omega = \psi^2@f$ and apply the
 * usual "twist" for negacyclic convolution:
 *
 *  - Forward transform multiplies inputs by @f$\psi^{2i+1}@f$.
 *  - Inverse transform multiplies by @f$\psi^{-(2i+1)}@f$ and @f$n^{-1}@f$.
 *
 */
class NTT {
public:
    /**
     * @brief Construct an NTT instance.
     *
     * @param n          Transform size (must be a power of two).
     * @param modulus_q  Prime modulus.
     * @param negacyclic If true (default), configure for negacyclic
     *                   convolution over Z_q[x]/(x^n + 1) using a
     *                   primitive 2n‑th root of unity. If false, use a
     *                   standard cyclic NTT of length n.
     *
     * @throws std::invalid_argument if n is not a power of two, or if the
     *         modulus does not admit the required root of unity.
     */
    NTT(std::size_t n, std::uint64_t modulus_q, bool negacyclic = true);

    /**
     * @brief In‑place forward NTT on a coefficient vector.
     *
     * @param a Vector of length n with entries in [0, q).
     *
     * @throws std::invalid_argument if a.size() != n.
     */
    void forward(std::vector<std::uint64_t>& a) const;

    /**
     * @brief In‑place inverse NTT on a coefficient vector.
     *
     * @param a Vector of length n in the NTT domain.
     *
     * @throws std::invalid_argument if a.size() != n.
     */
    void inverse(std::vector<std::uint64_t>& a) const;

    /**
     * @brief Convenience overloads operating directly on Polynomial.
     */
    void forward(Polynomial& poly) const;
    void inverse(Polynomial& poly) const;

    /** @return Transform size n. */
    std::size_t size() const { return n_; }

    /** @return Modulus q. */
    std::uint64_t modulus() const { return q_; }

    /** @return True if configured for negacyclic convolution. */
    bool isNegacyclic() const { return negacyclic_; }

private:
    std::size_t n_;
    std::uint64_t q_;
    bool negacyclic_;

    // For the underlying length‑n NTT we use an n‑th primitive root omega.
    std::uint64_t omega_;      ///< primitive n‑th root of unity
    std::uint64_t omega_inv_;  ///< inverse of omega
    std::uint64_t n_inv_;      ///< modular inverse of n modulo q

    // When negacyclic_ == true we additionally use a primitive 2n‑th root
    // psi with psi^2 = omega and psi^n = -1 (mod q).
    std::uint64_t psi_;        ///< primitive 2n‑th root (only for negacyclic)
    std::uint64_t psi_inv_;
    std::vector<std::uint64_t> psi_powers_;      ///< psi^{2i+1}
    std::vector<std::uint64_t> psi_powers_inv_;  ///< psi^{-(2i+1)}

    // Utility helpers
    static bool isPowerOfTwo(std::size_t n);

    static std::uint64_t modAdd(std::uint64_t a, std::uint64_t b, std::uint64_t m) {
        std::uint64_t res = a + b;
        if (res >= m) res -= m;
        return res;
    }

    static std::uint64_t modSub(std::uint64_t a, std::uint64_t b, std::uint64_t m) {
        return (a >= b) ? (a - b) : (a + m - b);
    }

    static std::uint64_t modMul(std::uint64_t a, std::uint64_t b, std::uint64_t m) {
        // We intentionally avoid non‑standard integer types like __int128
        // to keep this project strictly ISO C++ compliant.
        //
        // The current parameter sets use small moduli (q < 2^16), so the
        // plain 64‑bit multiplication cannot overflow a 128‑bit intermediate
        // and is safe here. If larger q are ever introduced, this routine
        // should be upgraded to use Montgomery or Barrett reduction.
        return (a * b) % m;
    }

    static std::uint64_t modPow(std::uint64_t base, std::uint64_t exp, std::uint64_t m) {
        std::uint64_t res = 1;
        while (exp) {
            if (exp & 1) res = modMul(res, base, m);
            base = modMul(base, base, m);
            exp >>= 1;
        }
        return res;
    }

    static std::uint64_t modInverse(std::uint64_t a, std::uint64_t m);

    /**
     * @brief Return a precomputed primitive 2n‑th root of unity psi for
     *        supported (n, q) pairs. The value satisfies psi^n = -1 (mod q).
     */
    static std::uint64_t getPrecomputedPsi(std::size_t n, std::uint64_t q);

    void bitReverse(std::vector<std::uint64_t>& a) const;

    void ntt(std::vector<std::uint64_t>& a, bool inverse) const;
};

#endif // NTT_H
