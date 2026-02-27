#include "Vault.hpp"
#include "TOTP.hpp"
#include "UI.hpp"
#include "I18n.hpp"
#include "ProfileManager.hpp" // Include ProfileManager
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <limits> // Required for numeric_limits

// TODO: Extract the raw strings here to the localized jsons

const std::string CIPHERLOCK_VERSION = "1.0.0";

// Forward declaration for UI::print_usage to update it later
namespace UI {
    void print_usage();
}

// Function to handle profile-related commands
void run_profile_command(int argc, char* argv[]) { // TODO: Test this method (modified by Gemini)
    if (argc < 3) {
        std::cerr << I18n::instance().t("profile.error_subcommand_missing") << "\n";
        UI::print_usage();
        return;
    }

    std::string subcommand = argv[2];

    try {
        cipherLock::ProfileManager::ensureUserProfileBaseDirExists();

        if (subcommand == "create") {
            std::string profileName;
            std::string description;

            if (argc > 3) { // Profile name provided directly
                profileName = argv[3];
            } else {
                std::cout << I18n::instance().t("profile.enter_name");
                std::cin >> profileName;
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Consume the leftover newline
            }

            std::cout << I18n::instance().t("profile.enter_description");
            std::getline(std::cin, description); // Read description, potentially with spaces

            if (cipherLock::ProfileManager::listProfiles().empty()) {
                // If this is the first profile, make it active by default
                cipherLock::UserProfile newProfile = {profileName, description};
                cipherLock::ProfileManager::saveProfile(newProfile);
                cipherLock::ProfileManager::setActiveProfile(profileName);
                std::cout << I18n::instance().t("profile.created_and_set_active", {{"name", profileName}}) << "\n";
            } else {
                cipherLock::UserProfile newProfile = {profileName, description};
                cipherLock::ProfileManager::saveProfile(newProfile);
                std::cout << I18n::instance().t("profile.created_successfully", {{"name", profileName}}) << "\n";
            }
        } else if (subcommand == "list") {
            std::cout << I18n::instance().t("profile.available_profiles") << "\n";
            std::vector<std::string> profiles = cipherLock::ProfileManager::listProfiles();
            std::string activeProfileName = cipherLock::ProfileManager::getActiveProfileName();
            if (profiles.empty()) {
                std::cout << I18n::instance().t("profile.no_profiles_found") << "\n";
            } else {
                for (const auto& p : profiles) {
                    std::cout << "- " << p << (p == activeProfileName ? " (" + I18n::instance().t("profile.active") + ")" : "") << "\n";
                }
            }
        } else if (subcommand == "set-active") {
            std::string profileName;
            if (argc > 3) {
                profileName = argv[3];
            } else {
                std::cout << I18n::instance().t("profile.enter_name_to_set_active");
                std::cin >> profileName;
            }
            cipherLock::ProfileManager::setActiveProfile(profileName);
            std::cout << I18n::instance().t("profile.set_active_successfully", {{"name", profileName}}) << "\n";
        } else if (subcommand == "get-active") {
            std::string activeProfileName = cipherLock::ProfileManager::getActiveProfileName();
            if (activeProfileName.empty()) {
                std::cout << I18n::instance().t("profile.no_active_profile") << "\n";
            } else {
                std::cout << I18n::instance().t("profile.current_active_profile", {{"name", activeProfileName}}) << "\n";
            }
        } else {
            std::cerr << I18n::instance().t("profile.error_unknown_subcommand", {{"subcommand", subcommand}}) << "\n";
            UI::print_usage();
        }
    } catch (const std::runtime_error& e) {
        std::cerr << I18n::instance().t("profile.error_generic", {{"error_msg", e.what()}}) << "\n";
    }
}

void display_version() { // TODO: Test this method (modified by Gemini)
    std::cout << I18n::instance().t("ui.version", {{"version", CIPHERLOCK_VERSION}}) << std::endl;
}

void run_settings_menu() {
    bool running = true;
    while(running) {
        std::cout << "\n--- " << I18n::instance().t("settings.menu_title") << " ---\n";
        std::cout << I18n::instance().t("settings.menu_options") << "\n";
        std::cout << I18n::instance().t("ui.selection");

        int choice;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(1000, '\n');
            continue;
        }

        switch (choice) {
            case 1: { // Change Language
                std::cout << I18n::instance().t("settings.enter_lang_code");
                std::string lang_code;
                std::cin >> lang_code;
                std::string old_locale = I18n::instance().getCurrentLocale();
                I18n::instance().load(lang_code, "../locales");
                if (I18n::instance().getCurrentLocale() == lang_code) {
                    std::cout << I18n::instance().t("settings.lang_changed", {{"lang", I18n::instance().getLanguageName()}}) << std::endl;
                } else {
                    I18n::instance().load(old_locale, "../locales"); // Revert on failure
                    std::cout << I18n::instance().t("settings.lang_change_failed", {{"lang", lang_code}}) << "\n";
                }
                break;
            }
            case 2: { // List Languages
                std::cout << I18n::instance().t("settings.available_languages") << "\n";
                for (const auto& lang : I18n::instance().getAvailableLanguages("../locales")) {
                    std::cout << "- " << lang << "\n";
                }
                break;
            }
            case 3: { // Back to Main Menu
                running = false;
                break;
            }
            default:
                std::cout << I18n::instance().t("ui.invalid_option") << "\n";
        }
    }
}

void run_hot_mode(const std::string& start_dir = ".") { // TODO: Test this method (modified by Gemini)
    Vault vault;
    // TODO: Change the super secret key to something else and then include it in the config.json
    std::string secret = "Sup3rS3cr3tK3y!";
    bool is_base32 = false;

    if (vault.load(start_dir)) {
        std::string vault_secret = vault.get_totp_secret();
        if (!vault_secret.empty()) {
            secret = vault_secret;
            is_base32 = true;
        }
        std::cout << "\033[1;32m" << I18n::instance().t("vault.vault_loaded", {{"path", start_dir}}) << "\033[0m" << std::endl;
    } else {
        std::cout << "\033[1;33m" << I18n::instance().t("vault.no_vault_at_path", {{"path", start_dir}}) << "\033[0m" << std::endl;
    }

    TOTP totp(secret, is_base32);
    
    bool running = true;
    while(running) {
        std::cout << "\n\033[1;32m" << I18n::instance().t("ui.hot_mode_active", {{"version", CIPHERLOCK_VERSION}}) << "\033[0m\n";
        std::cout << "\n\033[1;36m" << I18n::instance().t("ui.hot_mode_menu_options") << "\033[0m\n";
        std::cout << I18n::instance().t("ui.selection");
        int choice;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(1000, '\n');
            continue;
        }

        switch (choice) {
            case 1: {
                std::cout << I18n::instance().t("ui.path");
                std::string dir;
                std::cin >> dir;
                vault.setup(dir);
                break;
            }
            case 2: {
                std::cout << I18n::instance().t("ui.password");
                std::string pwd;
                std::cin >> pwd;
                vault.arm(pwd);
                break;
            }
            case 3: {
                std::cout << I18n::instance().t("ui.totp");
                std::string code;
                std::cin >> code;
                if (totp.verify(code)) {
                    std::cout << I18n::instance().t("ui.password");
                    std::string pwd;
                    std::cin >> pwd;
                    vault.disarm(pwd);
                } else {
                    std::cout << "\033[1;31m" << I18n::instance().t("ui.invalid_totp") << "\033[0m\n";
                }
                break;
            }
            case 4:
                std::cout << I18n::instance().t("ui.totp_display", {{"code", totp.generate_current()}, {"seconds", std::to_string(totp.get_seconds_remaining())}}) << "\n";
                break;
            case 5:
                vault.display_status();
                break;
            case 6:
                run_settings_menu();
                break;
            case 7:
                running = false;
                break;
            default:
                std::cout << I18n::instance().t("ui.invalid_option") << "\n";
        }
    }
}

void run_cold_mode(const std::string& src, const std::string& key_file, const std::string& dest) { // TODO: Test this method (modified by Gemini)
    std::cout << I18n::instance().t("ui.cold_mode_prefix") << I18n::instance().t("ui.cold_mode_active", {{"version", CIPHERLOCK_VERSION}}) << "\n";
    
    std::ifstream kf(key_file);
    if (!kf) {
        std::cerr << "\033[1;31m" << I18n::instance().t("vault.error_key_file", {{"file", key_file}}) << "\033[0m\n";
        return;
    }
    std::string key;
    std::getline(kf, key);
    
    Vault vault;
    if (vault.setup(src)) {
        std::cout << I18n::instance().t("vault.arming_progress") << "\n";
        vault.arm(key);
    }
}

int main(int argc, char* argv[]) {
    // Initialize localization
    I18n::instance().load("en", "../locales");

    std::string arg1 = (argc > 1) ? argv[1] : "";

    // 1. Handle basic informational commands that don't require a profile
    // These commands print usage/version/lang info and then exit.
    if (arg1 == "--help" || arg1 == "-h") {
        UI::print_usage();
        return 0;
    }

    if (arg1 == "--version" || arg1 == "-v") {
        display_version();
        return 0;
    }
    
    if (arg1 == "lang") {
        if (argc == 2) {
            std::cout << I18n::instance().t("lang_command.current_lang") << I18n::instance().getLanguageName() << std::endl;
        } else if (argc == 3) {
            std::string arg2 = argv[2];
            if (arg2 == "--list" || arg2 == "list") {
                std::cout << I18n::instance().t("lang_command.available_langs_title") << "\n";
                for (const auto& lang : I18n::instance().getAvailableLanguages("../locales")) {
                    std::cout << I18n::instance().t("lang_command.available_langs_prefix") << lang << std::endl;
                }
            } else {
                std::string new_locale = arg2;
                std::string old_lang_name = I18n::instance().getLanguageName();
                I18n::instance().load(new_locale, "../locales");
                
                if (I18n::instance().getCurrentLocale() == new_locale) {
                    std::cout << I18n::instance().t("lang_command.lang_changed_from_to", {{"old_lang_name", old_lang_name}, {"new_lang_name", I18n::instance().getLanguageName()}}) << std::endl;
                } else {
                    std::cerr << I18n::instance().t("lang_command.lang_change_failed", {{"lang", new_locale}}) << std::endl;
                    std::cerr << I18n::instance().t("lang_command.falling_back_lang", {{"lang", I18n::instance().getLanguageName()}}) << std::endl;
                }
            }
        }
        return 0;
    }

    if (arg1 == "profile") { // Profile commands should always work without requiring an active profile
        run_profile_command(argc, argv);
        return 0;
    }

    // 2. Determine active profile for welcome message and subsequent checks
    std::string activeProfileName;
    try {
        cipherLock::ProfileManager::ensureUserProfileBaseDirExists();
        activeProfileName = cipherLock::ProfileManager::getActiveProfileName();
    } catch (const std::runtime_error& e) {
        // Log error but don't prevent welcome display. This might happen if ~/.cipherlock is unreadable.
        std::cerr << I18n::instance().t("profile.warning_profile_info_failed", {{"error_msg", e.what()}}) << "\n";
    }

    // Display welcome UI for general invocation or unrecognized commands
    // Pass activeProfileName to UI::print_welcome
    UI::print_welcome(CIPHERLOCK_VERSION, I18n::instance().getLanguageName(), activeProfileName);

    // If no command is given (bare cipherlock call) or an unrecognized command is provided
    if (arg1.empty() || (arg1 != "boot" && arg1 != "init" && arg1 != "arm" && arg1 != "disarm" && arg1 != "profile" && arg1 != "lang" && arg1 != "--help" && arg1 != "-h" && arg1 != "--version" && arg1 != "-v")) {
        if (activeProfileName.empty()) {
            std::cout << I18n::instance().t("profile.no_active_profile_found_prompt") << "\n";
            std::cout << I18n::instance().t("profile.prompt_create_or_set") << "\n";
        }
        if (arg1.empty()) { // Only show usage for bare cipherlock call
            UI::print_usage();
        } else { // For unrecognized command, show error and usage
            std::cerr << I18n::instance().t("common.error_unrecognized_command", {{"cmd", arg1}}) << "\n";
            UI::print_usage();
        }
        return (arg1.empty() ? 0 : 1); // Exit with success for bare call, error for unrecognized command
    }

    // 3. Enforce active profile for commands that NEED it
    if (activeProfileName.empty()) {
        std::cerr << I18n::instance().t("profile.error_no_active_profile_critical") << "\n";
        std::cerr << I18n::instance().t("profile.prompt_create_or_set") << "\n";
        return 1; // Critical error, exit
    }

    // 4. Execute commands that require an active profile
    if (arg1 == "boot") {
        std::string target_dir = (argc >= 3) ? argv[2] : ".";
        run_hot_mode(target_dir);
        return 0;
    }

    if (arg1 == "init") {
        std::string target_dir = (argc >= 3) ? argv[2] : ".";
        Vault vault;
        if (!vault.setup(target_dir)) {
            std::cerr << I18n::instance().t("vault.error_init_failed", {{"path", target_dir}}) << "\n";
            return 1;
        }
        return 0;
    }

    if (arg1 == "arm") {
        std::string target_dir = (argc >= 3) ? argv[2] : ".";
        Vault vault;
        if (!vault.load(target_dir)) {
            std::cerr << I18n::instance().t("vault.error_no_vault", {{"path", target_dir}}) << "\n";
            return 1;
        }
        
        std::cout << I18n::instance().t("vault.enter_password_encrypt");
        std::string password;
        std::cin >> password;
        vault.arm(password);
        return 0;
    }

    if (arg1 == "disarm") {
        std::string target_dir = (argc >= 3) ? argv[2] : ".";
        Vault vault;
        if (!vault.load(target_dir)) {
            std::cerr << I18n::instance().t("vault.error_no_vault", {{"path", target_dir}}) << "\n";
            return 1;
        }

        std::string secret = vault.get_totp_secret();
        if (secret.empty()) {
            std::cerr << I18n::instance().t("vault.error_read_secret") << "\n";
            return 1;
        }

        TOTP totp(secret, true); // Use Base32 decoding
        std::cout << I18n::instance().t("vault.enter_totp");
        std::string code;
        std::cin >> code;

        if (totp.verify(code)) {
            std::cout << I18n::instance().t("vault.enter_password_decrypt");
            std::string password;
            std::cin >> password;
            vault.disarm(password);
        } else {
            std::cerr << I18n::instance().t("vault.invalid_totp") << "\n";
            return 1;
        }
        return 0;
    }

    // This block should ideally not be reached if all commands are correctly handled.
    // It acts as a final catch-all for any missed command handling, but should be rare.
    std::cerr << I18n::instance().t("common.error_unrecognized_command", {{"cmd", arg1}}) << "\n";
    UI::print_usage();
    return 1;
}