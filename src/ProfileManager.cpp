#include "ProfileManager.hpp"
#include <iostream> // For debugging, remove later
#include <cstdlib> // For getenv
#include <algorithm> // For std::find_if
#include <iterator>  // For std::istreambuf_iterator
#include <iomanip>   // For std::setw
#include <string>    // For std::to_string
#include <stdexcept> // For std::out_of_range, std::runtime_error
#include <vector>    // For std::vector
#include <filesystem> // For std::filesystem
#include <cstdlib>   // For std::getenv
#include <fstream>   // For std::ifstream, std::ofstream
#include <iostream>  // For std::cerr
#include <cstring>   // For std::strerror

#include "nlohmann/json.hpp" // Assuming nlohmann/json.hpp is available

#include "ProfileManager.hpp"


namespace cipherLock {

namespace fs = std::filesystem;

// Helper to get environment variable
static std::string getEnv(const std::string& var) {
    if (const char* env_p = std::getenv(var.c_str())) {
        return env_p;
    }
    return "";
}

fs::path ProfileManager::getUserProfileBaseDir() { // TODO: Test this method (Gemini)
    fs::path homeDir;

// TODO: Set the environmental variable properties properly
#ifdef _WIN32
    homeDir = getEnv("USERPROFILE");
    if (homeDir.empty()) {
        throw std::runtime_error("ERROR: Could not determine USERPROFILE environment variable on Windows.");
    }
#else // __APPLE__ or __linux__
    homeDir = getEnv("HOME");
    if (homeDir.empty()) {
        throw std::runtime_error("ERROR: Could not determine HOME environment variable.");
    }
#endif

    return homeDir / ".cipherlock";
}

void ProfileManager::ensureUserProfileBaseDirExists() { // TODO: Test this method (Gemini)
    fs::path baseDir = getUserProfileBaseDir(); // This is ~/.cipherlock
    fs::path profilesDir = baseDir / "profiles";

    if (!fs::exists(baseDir)) {
        std::error_code ec;
        if (!fs::create_directories(baseDir, ec)) {
            throw std::runtime_error("ERROR: Failed to create base user profile directory: " + baseDir.string() + " (" + ec.message() + ")");
        }
    }

    if (!fs::exists(profilesDir)) {
        std::error_code ec;
        if (!fs::create_directories(profilesDir, ec)) {
            throw std::runtime_error("ERROR: Failed to create profiles subdirectory: " + profilesDir.string() + " (" + ec.message() + ")");
        }
    }
}

fs::path ProfileManager::getProfilePath(const std::string& profileName) { // TODO: Test this method (Gemini)
    return getUserProfileBaseDir() / "profiles" / profileName / "profile.json";
}

UserProfile ProfileManager::loadProfile(const std::string& profileName) { // TODO: Test this method (Gemini)
    fs::path profilePath = getProfilePath(profileName);
    if (!fs::exists(profilePath)) {
        throw std::runtime_error("ERROR: Profile '" + profileName + "' not found at " + profilePath.string());
    }

    std::ifstream ifs(profilePath);
    if (!ifs.is_open()) {
        throw std::runtime_error("ERROR: Failed to open profile file for reading: " + profilePath.string());
    }

    nlohmann::json j;
    try {
        ifs >> j;
        return j.get<UserProfile>();
    } catch (const nlohmann::json::exception& e) {
        throw std::runtime_error("ERROR: Failed to parse profile file '" + profileName + "': " + e.what());
    }
}

void ProfileManager::saveProfile(const UserProfile& profile) { // TODO: Test this method (Gemini)
    ensureUserProfileBaseDirExists(); // Ensures ~/.cipherlock/ and ~/.cipherlock/profiles/ exist

    fs::path profileDir = getUserProfileBaseDir() / "profiles" / profile.name;
    if (!fs::exists(profileDir)) { // Check if ~/.cipherlock/profiles/iodevblue exists
        std::error_code ec_dir;
        if (!fs::create_directories(profileDir, ec_dir)) {
            throw std::runtime_error("ERROR: Failed to create profile directory: " + profileDir.string() + " (" + ec_dir.message() + ")");
        }
#ifndef _WIN32 // Apply permissions only on non-Windows systems
        // Set permissions for the newly created profile directory to owner-only read/write/execute (0700)
        fs::permissions(profileDir, fs::perms::owner_all, ec_dir); // Reuse ec_dir for permissions error
        if (ec_dir) {
            std::cerr << "Warning: Failed to set permissions for profile directory: " + profileDir.string() + " (" + ec_dir.message() + ")\n";
        }
#endif
    }

    fs::path profilePath = getProfilePath(profile.name); // This is profileDir / "profile.json"
    std::ofstream ofs;
    // Attempt to open the file, capturing system-level errors
    ofs.open(profilePath, std::ios_base::out | std::ios_base::trunc);
    if (!ofs.is_open()) {
        throw std::runtime_error("ERROR: Failed to open profile file for writing: " + profilePath.string() + " (System error: " + std::strerror(errno) + ")");
    }

    nlohmann::json j = profile;
    ofs << std::setw(4) << j << std::endl; // Pretty print JSON
    if (ofs.fail()) {
        throw std::runtime_error("ERROR: Failed to write profile data to file: " + profilePath.string());
    }
}

std::vector<std::string> ProfileManager::listProfiles() { // TODO: Test this method (Gemini)
    std::vector<std::string> profiles;
    fs::path baseDir = getUserProfileBaseDir() / "profiles";

    if (!fs::exists(baseDir) || !fs::is_directory(baseDir)) {
        return profiles; // No profiles if directory doesn't exist or isn't a directory
    }

    for (const auto& entry : fs::directory_iterator(baseDir)) {
        if (entry.is_directory()) {
            std::string name = entry.path().filename().string();
            profiles.push_back(name);
        }
    }
    return profiles;
}

void ProfileManager::setActiveProfile(const std::string& profileName) { // TODO: Test this method (Gemini)
    fs::path profilePath = getProfilePath(profileName);
    if (!fs::exists(profilePath)) {
        throw std::runtime_error("ERROR: Cannot set active profile: Profile '" + profileName + "' does not exist.");
    }

    fs::path activeProfileMarker = getUserProfileBaseDir() / "active_profile.json";
    std::error_code ec;

    // Remove existing symlink/file if it exists
    if (fs::exists(activeProfileMarker, ec)) {
        fs::remove(activeProfileMarker, ec);
        if (ec) {
            throw std::runtime_error("ERROR: Failed to remove existing active profile link: " + ec.message());
        }
    }

    // Create a new file containing the active profile name
    std::ofstream ofs(activeProfileMarker);
    if (!ofs.is_open()) {
        throw std::runtime_error("ERROR: Failed to create active profile marker file: " + activeProfileMarker.string());
    }
    ofs << profileName << std::endl;
    if (ofs.fail()) {
        throw std::runtime_error("ERROR: Failed to write active profile name to marker file.");
    }
}

std::string ProfileManager::getActiveProfileName() { // TODO: Test this method (Gemini)
    fs::path activeProfileMarker = getUserProfileBaseDir() / "active_profile.json";
    if (!fs::exists(activeProfileMarker)) {
        return ""; // No active profile set
    }

    std::ifstream ifs(activeProfileMarker);
    if (!ifs.is_open()) {
        // This case should ideally not happen if fs::exists returned true
        return "";
    }

    std::string profileName;
    std::getline(ifs, profileName);
    return profileName;
}

UserProfile ProfileManager::getActiveProfile() { // TODO: Test this method (Gemini)
    std::string activeProfileName = getActiveProfileName();
    if (activeProfileName.empty()) {
        throw std::runtime_error("ERROR: No active profile is set.");
    }
    return loadProfile(activeProfileName);
}

void ProfileManager::backupProjectKey(const std::string& profileName, const std::string& projectUuid, const std::string& keyJson) { // TODO: Test this method (Gemini)
    fs::path backupDir = getUserProfileBaseDir() / "profiles" / profileName / "backups" / "keys";
    if (!fs::exists(backupDir)) {
        fs::create_directories(backupDir);
    }
    
    fs::path backupPath = backupDir / (projectUuid + ".clkey");
    std::ofstream ofs(backupPath);
    if (ofs) {
        ofs << keyJson;
    }
}

std::string ProfileManager::getProjectKeyBackup(const std::string& profileName, const std::string& projectUuid) { // TODO: Test this method (Gemini)
    fs::path backupPath = getUserProfileBaseDir() / "profiles" / profileName / "backups" / "keys" / (projectUuid + ".clkey");
    if (!fs::exists(backupPath)) return "";

    std::ifstream ifs(backupPath);
    if (!ifs) return "";

    return std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
}


auto ProfileManager::findContactByTitle(UserProfile& profile, const std::string& title) { // TODO: Test this method (Gemini)
    return std::find_if(profile.contacts.begin(), profile.contacts.end(),
                        [&title](const UserProfile::Contact& c) {
                            return c.title == title;
                        });
}

void ProfileManager::addContact(UserProfile& profile, const UserProfile::Contact& newContact) { // TODO: Test this method (Gemini)
    if (newContact.title.empty()) {
        throw std::runtime_error("ERROR: Contact title cannot be empty.");
    }
    // Check for duplicate title
    if (findContactByTitle(profile, newContact.title) != profile.contacts.end()) {
        throw std::runtime_error("ERROR: A contact with the title '" + newContact.title + "' already exists.");
    }
    profile.contacts.push_back(newContact);
}

void ProfileManager::editContact(UserProfile& profile, int index, const UserProfile::Contact& updatedContact) { // TODO: Test this method (Gemini)
    if (index < 0 || index >= profile.contacts.size()) {
        throw std::out_of_range("ERROR: Invalid contact index: " + std::to_string(index));
    }
    if (updatedContact.title.empty()) {
        throw std::runtime_error("ERROR: Contact title cannot be empty.");
    }

    // Check for duplicate title if the title is being changed and it conflicts with another existing contact (not itself)
    if (profile.contacts[index].title != updatedContact.title) {
        auto it = findContactByTitle(profile, updatedContact.title);
        if (it != profile.contacts.end()) {
            throw std::runtime_error("ERROR: A contact with the title '" + updatedContact.title + "' already exists.");
        }
    }

    profile.contacts[index] = updatedContact;
}

void ProfileManager::deleteContact(UserProfile& profile, int index) { // TODO: Test this method (Gemini)
    if (index < 0 || index >= profile.contacts.size()) {
        throw std::out_of_range("ERROR: Invalid contact index: " + std::to_string(index));
    }
    profile.contacts.erase(profile.contacts.begin() + index);
}

} // namespace cipherLock
