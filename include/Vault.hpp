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
    bool lock_vault(const std::string& password); // TODO: Test this method (Gemini)

    /**
     * @brief Decrypts all locked files in the vault.
     * @param password The password used to derive the decryption key.
     * @return true if successful.
     */
    bool unlock_vault(const std::string& password); // TODO: Test this method (Gemini)

    /**
     * @brief Generates a decryption token for a specific file.
     * @param filepath The path to the file to share.
     * @param password The master password.
     * @return std::string The JSON token as a string.
     */
    std::string share_file(const fs::path& filepath, const std::string& password); // TODO: Test this method (Gemini)

    /**
     * @brief Decrypts a file using a provided token.
     * @param token_json The JSON token string.
     * @param directory The root directory to search for the file.
     * @return true if successful.
     */
    bool decrypt_with_token(const std::string& token_json, const std::string& directory); // TODO: Test this method (Gemini)

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
     * @brief Checks if the current vault directory is initialized with a configuration.
     * @return true if initialized.
     */
    bool is_initialized() const; // TODO: Test this method (Gemini)

    /**
     * @brief Gets the current vault root directory.
     * @return std::string The path to the vault root.
     */
    std::string get_root() const; // TODO: Test this method (Gemini)

    /**
     * @brief Retrieves the TOTP secret stored in the vault config.
     * @return std::string The base32 encoded secret, or empty if not found.
     */
    std::string get_totp_secret(); // TODO: Test this method (Gemini)

private:
    fs::path vault_root;
    bool is_armed = false;

    // Header constants
    static constexpr const char* MAGIC = "CLOK";
    static constexpr unsigned char VERSION = 0x01;
    static constexpr size_t FILE_ID_LEN = 16;
    static constexpr size_t SALT_LEN = 16;
    static constexpr size_t IV_LEN = 16;
    static constexpr size_t HEADER_SIZE = 4 + 1 + FILE_ID_LEN + SALT_LEN + IV_LEN;

#pragma pack(push, 1)
    struct FileHeader {
        char magic[4];
        unsigned char version;
        unsigned char file_id[FILE_ID_LEN];
        unsigned char salt[SALT_LEN];
        unsigned char iv[IV_LEN];
    };
#pragma pack(pop)
    
    std::vector<std::regex> read_ignore_patterns(); // TODO: Test this method (Gemini)
    bool should_ignore(const fs::path& path, const std::vector<std::regex>& patterns); // TODO: Test this method (Gemini)
    
    bool encrypt_file(const fs::path& filepath, const std::string& password); // TODO: Test this method (Gemini)
    bool decrypt_file(const fs::path& filepath, const std::string& password); // TODO: Test this method (Gemini)

    void derive_master_key(const std::string& password, const unsigned char* salt, unsigned char* key); // TODO: Test this method (Gemini)
    void derive_file_key(const unsigned char* master_key, const unsigned char* file_id, unsigned char* file_key); // TODO: Test this method (Gemini)

    void ensure_gitignore_ignored(); // TODO: Test this method (Gemini)
    void display_laser_grid() const; // TODO: Test this method (Gemini)
};

#endif // VAULT_HPP
