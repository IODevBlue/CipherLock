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
     * @brief Structure to represent a milestone in the project.
     */
    struct Milestone {
        std::string id;
        std::string name;
        std::string description;
        bool is_released;
        double valuation;
        std::string currency;
        uint64_t created_at;
        uint64_t released_at;
    };

    /**
     * @brief Initializes a vault in the specified directory.
     * @param directory The root directory of the codebase.
     * @param profile_name The name of the profile initializing the vault.
     */
    bool setup(const std::string& directory, const std::string& profile_name = ""); // TODO: Test this method (Gemini)

    /**
     * @brief Interactively edits project metadata (name, valuation, etc).
     * @return true if successful.
     */
    bool edit_project_metadata(); // TODO: Test this method (Gemini)

    /**
     * @brief Creates a new milestone for the project.
     * @param name The name of the milestone.
     * @param valuation The valuation of the milestone.
     * @param currency The currency for the valuation.
     * @return true if successful.
     */
    bool create_milestone(const std::string& name, double valuation, const std::string& currency); // TODO: Test this method (Gemini)

    /**
     * @brief Lists all milestones in the project.
     */
    void list_milestones() const; // TODO: Test this method (Gemini)

    /**
     * @brief Releases a milestone, allowing its files to be decrypted.
     * @param milestone_id The ID of the milestone to release.
     * @return true if successful.
     */
    bool release_milestone(const std::string& milestone_id); // TODO: Test this method (Gemini)

    /**
     * @brief Interactively edits milestone metadata.
     * @param milestone_id The ID of the milestone to edit.
     * @return true if successful.
     */
    bool edit_milestone(const std::string& milestone_id); // TODO: Test this method (Gemini)

    /**
     * @brief Encrypts all non-ignored files in the vault.
     * @param milestone_id Optional ID of the milestone to associate files with.
     * @return true if successful.
     */
    bool lock_vault(const std::string& milestone_id = ""); // TODO: Test this method (Gemini)

    /**
     * @brief Decrypts all locked files in the vault.
     * @return true if successful.
     */
    bool unlock_vault(); // TODO: Test this method (Gemini)

    /**
     * @brief Generates a decryption token for a specific file.
     * @param filepath The path to the file to share.
     * @return std::string The JSON token as a string.
     */
    std::string share_file(const fs::path& filepath); // TODO: Test this method (Gemini)

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
     * @brief Gets the project currency.
     * @return std::string The currency code.
     */
    std::string get_currency() const { return project_currency; } // TODO: Test this method (Gemini)

private:
    fs::path vault_root;
    bool is_armed = false;
    std::vector<unsigned char> master_key; // The raw PMK (256-bit)
    std::string project_uuid;
    std::string active_profile_name; // Set during load/setup
    std::string project_name;
    std::string project_description;
    std::string project_client;
    std::string project_deadline;
    double project_valuation;
    std::string project_currency;
    uint64_t project_setup_date;
    std::string project_created_by;
    std::vector<Milestone> milestones;

    // Header constants
    static constexpr const char* MAGIC = "CLOK";
    static constexpr unsigned char VERSION_V1 = 0x01;
    static constexpr unsigned char VERSION_V2 = 0x02;
    static constexpr unsigned char VERSION = VERSION_V1;
    static constexpr size_t FILE_ID_LEN = 16;
    static constexpr size_t SALT_LEN = 16;
    static constexpr size_t IV_LEN = 16;

#pragma pack(push, 1)
    struct FileHeaderV1 {
        char magic[4];
        unsigned char version;
        unsigned char file_id[FILE_ID_LEN];
        unsigned char salt[SALT_LEN];
        unsigned char iv[IV_LEN];
    };

    struct FileHeaderV2 {
        char magic[4];
        unsigned char version;
        unsigned char file_id[FILE_ID_LEN];
        unsigned char milestone_id[FILE_ID_LEN];
        uint32_t version_counter;
        unsigned char salt[SALT_LEN];
        unsigned char iv[IV_LEN];
    };
    using FileHeader = FileHeaderV1;
#pragma pack(pop)
    
    std::vector<std::regex> read_ignore_patterns(); // TODO: Test this method (Gemini)
    bool should_ignore(const fs::path& path, const std::vector<std::regex>& patterns); // TODO: Test this method (Gemini)
    
    bool encrypt_file(const fs::path& filepath, const std::string& milestone_id = ""); // TODO: Test this method (Gemini)
    bool decrypt_file(const fs::path& filepath); // TODO: Test this method (Gemini)

    void derive_file_key(const unsigned char* key, const unsigned char* file_id, unsigned char* file_key); // TODO: Test this method (Gemini)
    void derive_milestone_key(const unsigned char* master_key, const unsigned char* milestone_id, unsigned char* milestone_key); // TODO: Test this method (Gemini)

    std::string generate_uuid(); // TODO: Test this method (Gemini)
    void uuid_to_bytes(const std::string& uuid, unsigned char* bytes); // TODO: Test this method (Gemini)
    std::string bytes_to_uuid(const unsigned char* bytes); // TODO: Test this method (Gemini)

    bool load_master_key(); // TODO: Test this method (Gemini)
    bool save_master_key(); // TODO: Test this method (Gemini)
    bool save_config(); // TODO: Test this method (Gemini)

    void ensure_gitignore_ignored(); // TODO: Test this method (Gemini)
    void display_laser_grid() const; // TODO: Test this method (Gemini)

};

#endif // VAULT_HPP
