#include "ProfileManager.hpp"
#include <iostream> // For debugging, remove later
#include <stdexcept>
#include <cstdlib> // For getenv
#include <fstream> // For file operations

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

    fs::path activeProfileSymlink = getUserProfileBaseDir() / "active_profile.json";
    std::error_code ec;

    // Remove existing symlink/file if it exists
    if (fs::exists(activeProfileSymlink, ec)) {
        fs::remove(activeProfileSymlink, ec);
        if (ec) {
            throw std::runtime_error("ERROR: Failed to remove existing active profile link: " + ec.message());
        }
    }

    // Create a new symlink to the chosen profile
    // Note: fs::create_symlink might not be available or work identically on all platforms
    // For simplicity, a file containing the profile name might be more robust cross-platform.
    // For now, let's use a simple file with the active profile name.
    std::ofstream ofs(activeProfileSymlink);
    if (!ofs.is_open()) {
        throw std::runtime_error("ERROR: Failed to create active profile marker file: " + activeProfileSymlink.string());
    }
    ofs << profileName << std::endl;
    if (ofs.fail()) {
        throw std::runtime_error("ERROR: Failed to write active profile name to marker file.");
    }
}

std::string ProfileManager::getActiveProfileName() { // TODO: Test this method (Gemini)
    fs::path activeProfileSymlink = getUserProfileBaseDir() / "active_profile.json";
    if (!fs::exists(activeProfileSymlink)) {
        return ""; // No active profile set
    }

    std::ifstream ifs(activeProfileSymlink);
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

} // namespace cipherLock
