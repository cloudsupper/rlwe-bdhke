#include <ntt.h>

#include <algorithm>

bool NTT::isPowerOfTwo(std::size_t n) {
    return n && ((n & (n - 1)) == 0);
}

std::uint64_t NTT::modInverse(std::uint64_t a, std::uint64_t m) {
    // Extended Euclidean algorithm
    std::int64_t t = 0, new_t = 1;
    std::int64_t r = static_cast<std::int64_t>(m);
    std::int64_t new_r = static_cast<std::int64_t>(a % m);

    while (new_r != 0) {
        std::int64_t q = r / new_r;
        std::int64_t tmp_t = t - q * new_t;
        t = new_t;
        new_t = tmp_t;

        std::int64_t tmp_r = r - q * new_r;
        r = new_r;
        new_r = tmp_r;
    }

    if (r > 1) {
        throw std::invalid_argument("Element has no modular inverse");
    }
    if (t < 0) t += static_cast<std::int64_t>(m);
    return static_cast<std::uint64_t>(t);
}

void NTT::bitReverse(std::vector<std::uint64_t>& a) const {
    std::size_t n = n_;
    std::size_t j = 0;
    for (std::size_t i = 1; i < n - 1; ++i) {
        std::size_t bit = n >> 1;
        for (; j & bit; bit >>= 1) {
            j ^= bit;
        }
        j ^= bit;
        if (i < j) {
            std::swap(a[i], a[j]);
        }
    }
}

void NTT::ntt(std::vector<std::uint64_t>& a, bool inverse) const {
    const std::uint64_t q = q_;

    bitReverse(a);

    std::size_t len = 2;
    while (len <= n_) {
        std::uint64_t wlen = inverse ? omega_inv_ : omega_;
        for (std::size_t i = len; i < n_; i <<= 1) {
            wlen = modMul(wlen, wlen, q);
        }

        for (std::size_t i = 0; i < n_; i += len) {
            std::uint64_t w = 1;
            for (std::size_t j = 0; j < len / 2; ++j) {
                std::uint64_t u = a[i + j];
                std::uint64_t v = modMul(a[i + j + len / 2], w, q);
                a[i + j] = modAdd(u, v, q);
                a[i + j + len / 2] = modSub(u, v, q);
                w = modMul(w, wlen, q);
            }
        }
        len <<= 1;
    }

    if (inverse) {
        for (std::size_t i = 0; i < n_; ++i) {
            a[i] = modMul(a[i], n_inv_, q);
        }
    }
}

NTT::NTT(std::size_t n, std::uint64_t modulus_q, bool negacyclic)
    : n_(n), q_(modulus_q), negacyclic_(negacyclic),
      omega_(0), omega_inv_(0), n_inv_(0), psi_powers_(nullptr), psi_powers_inv_(nullptr) {

    if (!isPowerOfTwo(n_)) {
        throw std::invalid_argument("NTT size n must be a power of two");
    }
    if (q_ < 2) {
        throw std::invalid_argument("Modulus q must be >= 2");
    }

    Logger::log("Initializing NTT with n=" + std::to_string(n_) +
                ", q=" + std::to_string(q_) +
                ", negacyclic=" + std::string(negacyclic_ ? "true" : "false"));

    if (!negacyclic_) {
        throw std::invalid_argument("Only negacyclic NTT is supported in this implementation");
    }
 
    std::uint64_t k = static_cast<std::uint64_t>(2 * n_);
    if ((q_ - 1) % k != 0) {
        throw std::invalid_argument("For negacyclic NTT we require q ≡ 1 (mod 2n)");
    }

    // Look up precomputed psi, psi^{-1} and twist tables for this (n, q).
    const ntt_tables::PsiTables* tbl = ntt_tables::getPsiTables(n_, q_);
    if (!tbl) {
        throw std::invalid_argument("NTT: no precomputed tables for given (n, q)");
    }

    // Underlying n‑point NTT uses omega = psi^2 (order n).
    omega_ = modMul(tbl->psi, tbl->psi, q_);
    omega_inv_ = modInverse(omega_, q_);

    n_inv_ = modInverse(static_cast<std::uint64_t>(n_), q_);

    if (negacyclic_) {
        // These already contain psi^{2i+1} and psi^{-(2i+1)} for i in [0, n-1].
        psi_powers_ = tbl->twist;
        psi_powers_inv_ = tbl->twist_inv;
    }

    Logger::log("NTT initialization complete");
}

void NTT::forward(std::vector<std::uint64_t>& a) const {
    if (a.size() != n_) {
        throw std::invalid_argument("NTT::forward: input size mismatch");
    }

    if (negacyclic_) {
        // Apply the negacyclic twist: a_i <- a_i * psi^{2i+1}
        for (std::size_t i = 0; i < n_; ++i) {
            a[i] = modMul(a[i], psi_powers_[i], q_);
        }
    }

    ntt(a, /*inverse=*/false);
}

void NTT::inverse(std::vector<std::uint64_t>& a) const {
    if (a.size() != n_) {
        throw std::invalid_argument("NTT::inverse: input size mismatch");
    }

    ntt(a, /*inverse=*/true);

    if (negacyclic_) {
        // Undo the twist: a_i <- a_i * psi^{-(2i+1)}
        for (std::size_t i = 0; i < n_; ++i) {
            a[i] = modMul(a[i], psi_powers_inv_[i], q_);
        }
    }
}

void NTT::forward(Polynomial& poly) const {
    if (poly.degree() != n_ || poly.getModulus() != q_) {
        throw std::invalid_argument("NTT::forward(Polynomial): ring dimension or modulus mismatch");
    }
    std::vector<std::uint64_t> tmp = poly.getCoeffs();
    forward(tmp);
    poly.setCoefficients(tmp);
}

void NTT::inverse(Polynomial& poly) const {
    if (poly.degree() != n_ || poly.getModulus() != q_) {
        throw std::invalid_argument("NTT::inverse(Polynomial): ring dimension or modulus mismatch");
    }
    std::vector<std::uint64_t> tmp = poly.getCoeffs();
    inverse(tmp);
    poly.setCoefficients(tmp);
}
