#ifndef SHA256_H
#define SHA256_H

#include <vector>
#include <string>
#include <cstdint>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "polynomial.h"

/**
 * @brief SHA-256 hashing utilities.
 *
 * This class provides a thin, exception-safe wrapper around the
 * OpenSSL EVP API for computing SHA-256 message digests over
 * byte vectors, strings, and polynomials.
 */
class SHA256 {
public:
    /**
     * @brief Compute the SHA-256 hash of a byte vector.
     *
     * @param data Input bytes.
     * @return Hash bytes of length hashSize().
     *
     * @throws std::runtime_error if the underlying OpenSSL calls fail.
     */
    static std::vector<uint8_t> hash(const std::vector<uint8_t>& data);

    /**
     * @brief Compute the SHA-256 hash of a string.
     *
     * The string is interpreted as a sequence of bytes using its
     * underlying representation.
     *
     * @param data Input string.
     * @return Hash bytes of length hashSize().
     */
    static std::vector<uint8_t> hash(const std::string& data);

    /**
     * @brief Compute the SHA-256 hash of a polynomial.
     *
     * The polynomial is first serialized to a byte vector via
     * Polynomial::toBytes() and then hashed.
     *
     * @param poly Polynomial to hash.
     * @return Hash bytes of length hashSize().
     */
    static std::vector<uint8_t> polyToHash(const Polynomial& poly);

    /**
     * @brief Get the SHA-256 digest size in bytes.
     *
     * @return Digest size (32 bytes).
     */
    static constexpr size_t hashSize() { return SHA256_DIGEST_LENGTH; }

private:
    /**
     * @brief Convert a raw OpenSSL digest buffer to a byte vector.
     *
     * @param digest Pointer to a buffer of SHA256_DIGEST_LENGTH bytes.
     * @return Vector containing the digest bytes.
     */
    static std::vector<uint8_t> digestToVector(const unsigned char* digest);
};

#endif // SHA256_H
