#include <polynomial.h>
#include <stdexcept>

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

    Logger::log("Multiplying polynomials:\n  " + toString() + "\n  " + other.toString());

    std::vector<uint64_t> temp(2 * ring_dim, 0);

    for (size_t i = 0; i < ring_dim; i++) {
        for (size_t j = 0; j < ring_dim; j++) {
            uint64_t prod = (static_cast<uint64_t>(coeffs[i]) * 
                           static_cast<uint64_t>(other.coeffs[j])) % modulus;
            temp[i + j] = (temp[i + j] + prod) % modulus;
        }
    }

    Logger::log("Intermediate multiplication result:\n  " + 
                Logger::vectorToString(temp, "  temp = "));
    Polynomial result(ring_dim, modulus);
    for (size_t i = 0; i < ring_dim; i++) {
        result[i] = temp[i];
        size_t higher_degree = i + ring_dim;
        while (higher_degree < temp.size()) {
            result[i] = mod(static_cast<int64_t>(result[i]) - 
                          static_cast<int64_t>(temp[higher_degree]), modulus);
            higher_degree += ring_dim;
        }
    }

    Logger::log("Final multiplication result after reduction:\n  " + result.toString());
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
