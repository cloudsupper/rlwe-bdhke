#include <polynomial.h>
#include <stdexcept>
#include <ntt.h>

/*
static Polynomial multiplySchoolbook(const Polynomial& a,
                                     const Polynomial& b) {
    const std::size_t n = a.degree();
    const std::uint64_t q = a.getModulus();

    if (n != b.degree() || q != b.getModulus()) {
        throw std::invalid_argument("Polynomials must be in the same ring");
    }

    Logger::log("[Schoolbook] Multiplying polynomials:\n  " + a.toString() +
                "\n  " + b.toString());

    const auto& a_coeffs = a.getCoeffs();
    const auto& b_coeffs = b.getCoeffs();

    std::vector<std::uint64_t> temp(2 * n, 0);

    for (std::size_t i = 0; i < n; i++) {
        for (std::size_t j = 0; j < n; j++) {
            std::uint64_t prod =
                (static_cast<std::uint64_t>(a_coeffs[i]) *
                 static_cast<std::uint64_t>(b_coeffs[j])) % q;
            temp[i + j] = (temp[i + j] + prod) % q;
        }
    }

    Logger::log("[Schoolbook] Intermediate multiplication result:\n  " +
                Logger::vectorToString(temp, "  temp = "));

    Polynomial result(n, q);
    for (std::size_t i = 0; i < n; i++) {
        std::uint64_t coeff = temp[i];
        std::size_t higher_degree = i + n;
        while (higher_degree < temp.size()) {
            // Reduce modulo x^n + 1 via c_i <- c_i - c_{i + kn} (mod q).
            const std::int64_t diff = static_cast<std::int64_t>(coeff) -
                                      static_cast<std::int64_t>(temp[higher_degree]);
            const std::int64_t m = static_cast<std::int64_t>(q);
            std::int64_t r = diff % m;
            if (r < 0) r += m;
            coeff = static_cast<std::uint64_t>(r);
            higher_degree += n;
        }
        result[i] = coeff;
    }

    Logger::log("[Schoolbook] Final multiplication result after reduction:\n  " +
                result.toString());
    return result;
}
*/

Polynomial Polynomial::polySignal() const {
    Polynomial result(ring_dim, modulus);
    uint64_t half_mod = modulus / 2;
    
    for (size_t i = 0; i < ring_dim; i++) {
        uint64_t coeff = coeffs[i];
        uint64_t dist_to_zero = std::min(coeff, modulus - coeff);
        uint64_t dist_to_half = std::min(
            (coeff >= half_mod) ? coeff - half_mod : half_mod - coeff,
            (coeff >= half_mod) ? modulus - coeff + half_mod : modulus - half_mod + coeff
        );
        
        result[i] = (dist_to_zero <= dist_to_half) ? 0 : half_mod;
    }
    
    Logger::log("Rounded polynomial coefficients to binary signal");
    return result;
}

Polynomial Polynomial::operator+(const Polynomial& other) const {
    if (ring_dim != other.ring_dim || modulus != other.modulus) {
        throw std::invalid_argument("Polynomials must be in the same ring");
    }

    Logger::log("Adding polynomials:\n  " + toString() + "\n  " + other.toString());

    Polynomial result(ring_dim, modulus);
    for (size_t i = 0; i < ring_dim; i++) {
        result[i] = (coeffs[i] + other.coeffs[i]) % modulus;
    }

    Logger::log("Addition result:\n  " + result.toString());
    return result;
}

Polynomial Polynomial::operator-(const Polynomial& other) const {
    if (ring_dim != other.ring_dim || modulus != other.modulus) {
        throw std::invalid_argument("Polynomials must be in the same ring");
    }

    Logger::log("Subtracting polynomials:\n  " + toString() + "\n  " + other.toString());

    Polynomial result(ring_dim, modulus);
    for (size_t i = 0; i < ring_dim; i++) {
        result[i] = mod(static_cast<int64_t>(coeffs[i]) - 
                       static_cast<int64_t>(other.coeffs[i]), modulus);
    }

    Logger::log("Subtraction result:\n  " + result.toString());
    return result;
}

Polynomial Polynomial::operator-() const {
    Logger::log("Negating polynomial:\n  " + toString());

    Polynomial result(ring_dim, modulus);
    for (size_t i = 0; i < ring_dim; i++) {
        result[i] = (coeffs[i] == 0) ? 0 : modulus - coeffs[i];
    }

    Logger::log("Negation result:\n  " + result.toString());
    return result;
}

Polynomial Polynomial::operator*(const Polynomial& other) const {
    if (ring_dim != other.ring_dim || modulus != other.modulus) {
        throw std::invalid_argument("Polynomials must be in the same ring");
    }

    Logger::log("Multiplying polynomials (NTT-accelerated where available):\n  " +
                toString() + "\n  " + other.toString());


    NTT ntt(ring_dim, modulus, /*negacyclic=*/true);

    std::vector<std::uint64_t> a_vec = coeffs;
    std::vector<std::uint64_t> b_vec = other.coeffs;

    ntt.forward(a_vec);
    ntt.forward(b_vec);

    for (std::size_t i = 0; i < ring_dim; ++i) {
        a_vec[i] = (a_vec[i] * b_vec[i]) % modulus;
    }

    ntt.inverse(a_vec);

    Polynomial result(ring_dim, modulus);
    result.setCoefficients(a_vec);

    Logger::log("NTT-based multiplication result:\n  " + result.toString());
    return result;
}

Polynomial Polynomial::operator*(uint64_t scalar) const {
    Logger::log("Multiplying polynomial by scalar " + std::to_string(scalar) + ":\n  " + toString());

    Polynomial result(ring_dim, modulus);
    for (size_t i = 0; i < ring_dim; i++) {
        result[i] = (coeffs[i] * scalar) % modulus;
    }

    Logger::log("Scalar multiplication result:\n  " + result.toString());
    return result;
}
