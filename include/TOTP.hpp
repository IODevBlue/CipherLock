#ifndef TOTP_HPP
#define TOTP_HPP

#include <string>
#include <vector>
#include <chrono>

/**
 * @brief Secure Time-based One-Time Passowrd (TOTP) implementation based on RFC 6238.
 * Handles generation and verification of time-based one-time passwords.
 */
class TOTP {
public:
    explicit TOTP(const std::string& secret = "", bool is_base32 = false); // TODO: Test this method (Gemini)
    ~TOTP(); // TODO: Test this method (Gemini)

    // Non-copyable for security
    TOTP(const TOTP&) = delete;
    TOTP& operator=(const TOTP&) = delete;

    /**
     * @brief Updates the secret key used for TOTP generation.
     * @param new_secret The new secret string.
     * @param is_base32 Whether the new secret is base32 encoded.
     */
    void update_secret(const std::string& new_secret, bool is_base32 = false); // TODO: Test this method (Gemini)

    /**
     * @brief Generates the current 6-digit TOTP code.
     * @return std::string The 6-digit code.
     */
    std::string generate_current(); // TODO: Test this method (Gemini)

    /**
     * @brief Verifies if a given code is valid for the current or adjacent time windows.
     * @param code The 6-digit code to verify.
     * @return true if valid, false otherwise.
     */
    bool verify(const std::string& code); // TODO: Test this method (Gemini)

    /**
     * @brief Returns the base32 encoded secret (useful for QR codes).
     */
    std::string get_base32_secret() const; // TODO: Test this method (Gemini)

    /**
     * @brief Returns the seconds remaining in the current time window.
     */
    int get_seconds_remaining() const; // TODO: Test this method (Gemini)

private:
    std::vector<unsigned char> secret_key;
    const int time_step = 30;
    const int digits = 6;

    std::string generate(uint64_t timestamp); // TODO: Test this method (Gemini)
    void zeroize_secret(); // TODO: Test this method (Gemini)
};

#endif // TOTP_HPP
