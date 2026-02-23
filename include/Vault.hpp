#ifndef VAULT_HPP
#define VAULT_HPP

#include <string>
#include <vector>
#include <filesystem>
#include <regex>

namespace fs = std::filesystem;

/**
 * @brief Core engine for codebase encryption and decryption.
 * Manages file traversal, ignore patterns, and AES-256 operations.
 */
class Vault {
public:
    Vault();
    ~Vault() = default; // TODO: Test this method (Gemini)

    /**
     * @brief Initializes a vault in the specified directory.
     * @param directory The root directory of the codebase.
     */
    bool setup(const std::string& directory); // TODO: Test this method (Gemini)

    /**
     * @brief Encrypts all non-ignored files in the vault.
     * @param password The password used to derive the encryption key.
     * @return true if successful.
     */
    bool arm(const std::string& password); // TODO: Test this method (Gemini)

    /**
     * @brief Decrypts all locked files in the vault.
     * @param password The password used to derive the decryption key.
     * @return true if successful.
     */
    bool disarm(const std::string& password); // TODO: Test this method (Gemini)

    /**
     * @brief Checks the current status of the vault (Armed/Disarmed).
     */
    void display_status() const; // TODO: Test this method (Gemini)

    /**
     * @brief Loads an existing vault configuration from the specified directory.
     * @param directory The root directory of the codebase.
     * @return true if a valid vault configuration is found.
     */
    bool load(const std::string& directory); // TODO: Test this method (Gemini)

    /**
     * @brief Retrieves the TOTP secret stored in the vault config.
     * @return std::string The base32 encoded secret, or empty if not found.
     */
    std::string get_totp_secret(); // TODO: Test this method (Gemini)

private:
    fs::path vault_root;
    bool is_armed = false;
    
    std::vector<std::regex> read_ignore_patterns(); // TODO: Test this method (Gemini)
    bool should_ignore(const fs::path& path, const std::vector<std::regex>& patterns); // TODO: Test this method (Gemini)
    
    bool encrypt_file(const fs::path& filepath, const std::string& password); // TODO: Test this method (Gemini)
    bool decrypt_file(const fs::path& filepath, const std::string& password); // TODO: Test this method (Gemini)

    void display_laser_grid() const; // TODO: Test this method (Gemini)
};

#endif // VAULT_HPP
