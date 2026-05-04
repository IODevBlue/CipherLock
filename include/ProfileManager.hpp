#ifndef PROFILE_MANAGER_HPP
#define PROFILE_MANAGER_HPP

#include <string>
#include <filesystem>
#include <stdexcept>
#include <vector>

#include "nlohmann/json.hpp" // Assuming nlohmann/json.hpp is available for profile data

namespace cipherLock {

namespace fs = std::filesystem;

/**
 * @brief Represents a user profile in CipherLock.
 *
 * This struct defines the basic data structure for a user profile.
 * It is designed to be easily serializable to and deserializable from JSON.
 */
struct UserProfile {
    /**
     * @brief Contact information for the profile.
     */
    struct Contact { // TODO: Test this method (Gemini)
        std::string title;
        std::string link;
    };

    std::string name;
    std::string full_name; // Optional full name
    std::vector<Contact> contacts; // List of contact links
    std::string description;
    std::string theme; // Default theme name
};

// Define how to convert UserProfile::Contact to and from nlohmann::json
inline void to_json(nlohmann::json& j, const UserProfile::Contact& c) { // TODO: Test this method (Gemini)
    j = nlohmann::json{{"title", c.title}, {"link", c.link}};
}

inline void from_json(const nlohmann::json& j, UserProfile::Contact& c) { // TODO: Test this method (Gemini)
    j.at("title").get_to(c.title);
    j.at("link").get_to(c.link);
}

// Define how to convert UserProfile to and from nlohmann::json
inline void to_json(nlohmann::json& j, const UserProfile& p) { // TODO: Test this method (Gemini)
    j = nlohmann::json{
        {"name", p.name},
        {"full_name", p.full_name},
        {"contacts", p.contacts},
        {"description", p.description},
        {"theme", p.theme}
    };
}

inline void from_json(const nlohmann::json& j, UserProfile& p) { // TODO: Test this method (Gemini)
    j.at("name").get_to(p.name);
    p.full_name = j.value("full_name", "");
    if (j.contains("contacts")) {
        j.at("contacts").get_to(p.contacts);
    }
    j.at("description").get_to(p.description);
    p.theme = j.value("theme", "default");
}

/**
 * @brief Manages user profiles for CipherLock, including platform-specific
 *        directory handling and profile data persistence.
 */
class ProfileManager {
public:
    /**
     * @brief Get the base directory for CipherLock user profiles.
     *
     * This method determines the appropriate location for user profiles
     * based on the operating system.
     *
     * @return The absolute path to the CipherLock user profile directory.
     * @throws std::runtime_error if the home directory cannot be determined.
     */
    static fs::path getUserProfileBaseDir();

    /**
     * @brief Ensures that the CipherLock user profile base directory exists.
     *
     * If the directory does not exist, it will be created with appropriate
     * permissions.
     *
     * @throws std::runtime_error if the directory cannot be created.
     */
    static void ensureUserProfileBaseDirExists();

    /**
     * @brief Loads a user profile by its name.
     *
     * @param profileName The name of the profile to load.
     * @return The loaded UserProfile object.
     * @throws std::runtime_error if the profile file does not exist or
     *         cannot be parsed.
     */
    static UserProfile loadProfile(const std::string& profileName);

    /**
     * @brief Saves a user profile.
     *
     * @param profile The UserProfile object to save.
     * @throws std::runtime_error if the profile cannot be saved.
     */
    static void saveProfile(const UserProfile& profile);

    /**
     * @brief Lists the names of all available user profiles.
     *
     * @return A vector of strings, where each string is the name of a profile.
     */
    static std::vector<std::string> listProfiles();

    /**
     * @brief Sets a profile as the active profile.
     *
     * This typically involves creating a symbolic link or a special file
     * pointing to the active profile's data.
     *
     * @param profileName The name of the profile to set as active.
     * @throws std::runtime_error if the profile does not exist or
     *         cannot be set as active.
     */
    static void setActiveProfile(const std::string& profileName);

    /**
     * @brief Gets the name of the currently active profile.
     *
     * @return The name of the active profile, or an empty string if none is set.
     */
    static std::string getActiveProfileName();

    /**
     * @brief Gets the currently active profile.
     *
     * @return The loaded UserProfile object for the active profile.
     * @throws std::runtime_error if no active profile is set or
     *         the active profile cannot be loaded.
     */
    static UserProfile getActiveProfile();

    /**
     * @brief Backs up a project's master key to the profile directory.
     * @param profileName The name of the profile.
     * @param projectUuid The unique ID of the project.
     * @param keyJson The JSON content of the master key file.
     */
    static void backupProjectKey(const std::string& profileName, const std::string& projectUuid, const std::string& keyJson);

    /**
     * @brief Retrieves a backed-up project master key from the profile directory.
     * @param profileName The name of the profile.
     * @param projectUuid The unique ID of the project.
     * @return The JSON content of the backed-up key, or empty if not found.
     */
    static std::string getProjectKeyBackup(const std::string& profileName, const std::string& projectUuid);

private:
    /**
     * @brief Returns the full path to a profile file given its name.
     * @param profileName The name of the profile.
     * @return The fs::path to the profile file.
     */
    static fs::path getProfilePath(const std::string& profileName);
};

} // namespace cipherLock

#endif // PROFILE_MANAGER_HPP
