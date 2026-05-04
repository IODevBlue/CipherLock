#include "Vault.hpp"
#include "UI.hpp"
#include "I18n.hpp"
#include "ProfileManager.hpp" // Include ProfileManager
#include "Theme.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <limits> // Required for numeric_limits

// TODO: Hot and cold mode are now deprecated terms. Remove them and rename the usages.

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
                cipherLock::UserProfile newProfile = {profileName, "", {}, description, "default"};
                cipherLock::ProfileManager::saveProfile(newProfile);
                cipherLock::ProfileManager::setActiveProfile(profileName);
                std::cout << I18n::instance().t("profile.created_and_set_active", {{"name", profileName}}) << "\n";
            } else {
                cipherLock::UserProfile newProfile = {profileName, "", {}, description, "default"};
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
    std::cout << Theme::instance().color(Theme::SUCCESS) << I18n::instance().t("ui.version", {{"version", CIPHERLOCK_VERSION}}) << Theme::instance().color(Theme::RESET) << std::endl;
}

void run_settings_menu() {
    bool running = true;
    while(running) {
        std::cout << "\n" << Theme::instance().color(Theme::PRIMARY) << "--- " << I18n::instance().t("settings.menu_title") << " ---" << Theme::instance().color(Theme::RESET) << "\n";
        std::cout << Theme::instance().color(Theme::INFO) << I18n::instance().t("settings.menu_options") << Theme::instance().color(Theme::RESET) << "\n";
        std::cout << Theme::instance().color(Theme::PRIMARY) << I18n::instance().t("ui.selection") << Theme::instance().color(Theme::RESET);

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

                if (lang_code == "q" || lang_code == "Q") break;

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
            case 3: { // Change Theme
                std::cout << I18n::instance().t("settings.enter_theme_name");
                std::string theme_name;
                std::cin >> theme_name;

                if (theme_name == "q" || theme_name == "Q") break;

                if (Theme::instance().load(theme_name, "../themes")) {
                    try {
                        auto profile = cipherLock::ProfileManager::getActiveProfile();
                        profile.theme = theme_name;
                        cipherLock::ProfileManager::saveProfile(profile);
                    } catch (...) {}
                    std::cout << I18n::instance().t("settings.theme_changed", {{"theme", theme_name}}) << std::endl;
                } else {
                    std::cout << I18n::instance().t("settings.theme_change_failed", {{"theme", theme_name}}) << "\n";
                }
                break;
            }
            case 4: { // List Themes
                std::cout << I18n::instance().t("settings.available_themes") << "\n";
                for (const auto& theme : Theme::instance().getAvailableThemes("../themes")) {
                    std::cout << "- " << theme << (theme == Theme::instance().getCurrentThemeName() ? " *" : "") << "\n";
                }
                break;
            }
            case 5: { // Back to Main Menu
                running = false;
                break;
            }
            default:
                std::cout << I18n::instance().t("ui.invalid_option") << "\n";
        }
    }
}

void run_milestone_menu(Vault& vault) { // TODO: Test this method (Gemini)
    bool running = true;
    while(running) {
        std::cout << "\n" << Theme::instance().color(Theme::PRIMARY) << "--- " << I18n::instance().t("project.milestone_menu_title") << " ---" << Theme::instance().color(Theme::RESET) << "\n";
        std::cout << Theme::instance().color(Theme::INFO) << I18n::instance().t("project.milestone_menu_options") << Theme::instance().color(Theme::RESET) << "\n";
        std::cout << Theme::instance().color(Theme::PRIMARY) << I18n::instance().t("ui.selection") << Theme::instance().color(Theme::RESET);

        int choice;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(1000, '\n');
            continue;
        }

        switch (choice) {
            case 1: // List
                vault.list_milestones();
                break;
            case 2: { // Create
                std::cout << I18n::instance().t("project.enter_milestone_name");
                std::string name;
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                std::getline(std::cin, name);
                if (name.empty() || name == "q" || name == "Q") break;

                std::cout << I18n::instance().t("project.enter_milestone_valuation");
                std::string val_str;
                std::getline(std::cin, val_str);
                double valuation = 0.0;
                if (!val_str.empty() && val_str != "q" && val_str != "Q") {
                    try {
                        valuation = std::stod(val_str);
                    } catch (...) {}
                }
                
                // Get project currency
                std::string currency = vault.get_currency();
                if (currency.empty()) currency = "USD";

                vault.create_milestone(name, valuation, currency);
                break;
            }
            case 3: { // Edit
                std::cout << I18n::instance().t("project.enter_milestone_id");
                std::string m_id;
                std::cin >> m_id;
                vault.edit_milestone(m_id);
                break;
            }
            case 4: { // Release
                std::cout << I18n::instance().t("project.enter_milestone_id");
                std::string m_id;
                std::cin >> m_id;
                vault.release_milestone(m_id);
                break;
            }
            case 5: // Back
                running = false;
                break;
            default:
                std::cout << I18n::instance().t("ui.invalid_option") << "\n";
        }
    }
}

void run_hot_mode(const std::string& start_dir = ".", const std::string& active_profile = "") { // TODO: Test this method (modified by Gemini)
    Vault vault;

    if (vault.load(start_dir)) {
        std::cout << Theme::instance().color(Theme::SUCCESS) << I18n::instance().t("vault.vault_loaded", {{"path", start_dir}}) << Theme::instance().color(Theme::RESET) << std::endl;
    } else {
        std::cout << Theme::instance().color(Theme::SECONDARY) << I18n::instance().t("vault.no_vault_at_path", {{"path", start_dir}}) << Theme::instance().color(Theme::RESET) << std::endl;
        vault.setup(start_dir, active_profile);
    }

    bool running = true;
    while(running) {
        bool initialized = vault.is_initialized();
        
        std::string menu = "\n" + Theme::instance().color(Theme::PRIMARY);
        if (initialized) {
            menu += I18n::instance().t("ui.hot_mode_menu_switch");
        } else {
            menu += I18n::instance().t("ui.hot_mode_menu_setup");
        }
        menu += I18n::instance().t("ui.hot_mode_menu_common") + Theme::instance().color(Theme::RESET) + "\n";
        
        std::cout << menu;
        std::cout << Theme::instance().color(Theme::PRIMARY) << I18n::instance().t("ui.selection") << Theme::instance().color(Theme::RESET);
        int choice;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(1000, '\n');
            continue;
        }

        switch (choice) {
            case 1: {
                if (initialized) {
                    std::cout << I18n::instance().t("ui.path", {{"hint", I18n::instance().t("ui.switch_cancel_hint")}});
                    std::string dir;
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                    std::getline(std::cin, dir);
                    
                    if (dir.empty() || dir == "q" || dir == "Q") break;

                    if (fs::exists(dir)) {
                        if (!vault.load(dir)) {
                            vault.setup(dir, active_profile);
                        }
                    } else {
                        std::cout << I18n::instance().t("ui.folder_not_found", {{"path", dir}}) << "\n";
                        std::cout << I18n::instance().t("ui.ask_create_folder");
                        std::string answer;
                        std::cin >> answer;
                        if (answer == "y" || answer == "Y" || answer == "o" || answer == "O") {
                            vault.setup(dir, active_profile);
                        }
                    }
                } else {
                    vault.setup(vault.get_root(), active_profile);
                }
                break;
            }
            case 2: {
                vault.lock_vault();
                break;
            }
            case 3: {
                vault.unlock_vault();
                break;
            }
            case 4:
                vault.display_status();
                break;
            case 5:
                vault.edit_project_metadata();
                break;
            case 6:
                run_milestone_menu(vault);
                break;
            case 7:
                run_settings_menu();
                break;
            case 8:
                running = false;
                break;
            default:
                std::cout << Theme::instance().color(Theme::ERROR) << I18n::instance().t("ui.invalid_option") << Theme::instance().color(Theme::RESET) << "\n";
                break;
        }
    }
}

int main(int argc, char* argv[]) {
    // Initialize localization


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
        
        if (!activeProfileName.empty()) {
            auto profile = cipherLock::ProfileManager::getActiveProfile();
            if (!profile.theme.empty()) {
                Theme::instance().load(profile.theme, "../themes");
            }
        }
    } catch (const std::runtime_error& e) {
        // Log error but don't prevent welcome display. This might happen if ~/.cipherlock is unreadable.
        std::cerr << Theme::instance().color(Theme::ERROR) << I18n::instance().t("profile.warning_profile_info_failed", {{"error_msg", e.what()}}) << Theme::instance().color(Theme::RESET) << "\n";
    }

    // Display welcome UI for general invocation or unrecognized commands
    // Pass activeProfileName to UI::print_welcome
    UI::print_welcome(CIPHERLOCK_VERSION, I18n::instance().getLanguageName(), activeProfileName);

    // If no command is given (bare cipherlock call) or an unrecognized command is provided
    if (arg1.empty() || (arg1 != "boot" && arg1 != "edit" && arg1 != "share" && arg1 != "unlock-file" && arg1 != "profile" && arg1 != "lang" && arg1 != "--help" && arg1 != "-h" && arg1 != "--version" && arg1 != "-v")) {
        if (activeProfileName.empty()) {
            std::cout << I18n::instance().t("profile.no_active_profile_found_prompt") << "\n";
            std::cout << I18n::instance().t("profile.prompt_create_or_set") << "\n";
        }
        if (arg1.empty()) { // Only show usage for bare cipherlock call
            UI::print_usage();
        } else { // For unrecognized command, show error and usage
            std::cerr << Theme::instance().color(Theme::ERROR) << I18n::instance().t("common.error_unrecognized_command", {{"cmd", arg1}}) << Theme::instance().color(Theme::RESET) << "\n";
            UI::print_usage();
        }
        return (arg1.empty() ? 0 : 1); // Exit with success for bare call, error for unrecognized command
    }

    // 3. Enforce active profile for commands that NEED it
    if (activeProfileName.empty()) {
        std::cerr << Theme::instance().color(Theme::ERROR) << I18n::instance().t("profile.error_no_active_profile_critical") << Theme::instance().color(Theme::RESET) << "\n";
        std::cerr << I18n::instance().t("profile.prompt_create_or_set") << "\n";
        return 1; // Critical error, exit
    }

    // 4. Execute commands that require an active profile
    if (arg1 == "edit") {
        if (argc >= 3 && std::string(argv[2]) == "--project") {
            std::string target_dir = (argc >= 4) ? argv[3] : ".";
            Vault vault;
            if (vault.load(target_dir)) {
                vault.edit_project_metadata();
            } else {
                std::cerr << Theme::instance().color(Theme::ERROR) << I18n::instance().t("vault.error_no_vault", {{"path", target_dir}}) << Theme::instance().color(Theme::RESET) << "\n";
            }
            return 0;
        }
    }

    if (arg1 == "boot") {
        std::string target_dir = (argc >= 3) ? argv[2] : ".";
        run_hot_mode(target_dir, activeProfileName);
        return 0;
    }

    if (arg1 == "share") {
        if (argc < 3) {
            std::cerr << "Usage: cipherlock share <file_path> [vault_dir]\n";
            return 1;
        }
        std::string file_path = argv[2];
        std::string target_dir = (argc >= 4) ? argv[3] : ".";
        Vault vault;
        if (!vault.load(target_dir)) {
            std::cerr << Theme::instance().color(Theme::ERROR) << I18n::instance().t("vault.error_no_vault", {{"path", target_dir}}) << Theme::instance().color(Theme::RESET) << "\n";
            return 1;
        }

        std::string token = vault.share_file(file_path);
        if (token.empty()) {
            std::cerr << Theme::instance().color(Theme::ERROR) << "Failed to generate token for file: " << file_path << Theme::instance().color(Theme::RESET) << "\n";
            return 1;
        }

        std::string token_file = file_path + ".cltoken";
        std::ofstream out(token_file);
        out << token;
        std::cout << Theme::instance().color(Theme::SUCCESS) << "Token generated successfully: " << token_file << Theme::instance().color(Theme::RESET) << "\n";
        return 0;
    }

    if (arg1 == "unlock-file") {
        if (argc < 3) {
            std::cerr << "Usage: cipherlock unlock-file <token_file> [vault_dir]\n";
            return 1;
        }
        std::string token_file = argv[2];
        std::string target_dir = (argc >= 4) ? argv[3] : ".";
        
        std::ifstream in(token_file);
        if (!in) {
            std::cerr << Theme::instance().color(Theme::ERROR) << "Failed to open token file: " << token_file << Theme::instance().color(Theme::RESET) << "\n";
            return 1;
        }
        std::string token_json((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        
        Vault vault;
        if (vault.decrypt_with_token(token_json, target_dir)) {
            std::cout << Theme::instance().color(Theme::SUCCESS) << "File decrypted successfully using token.\n" << Theme::instance().color(Theme::RESET);
        } else {
            std::cerr << Theme::instance().color(Theme::ERROR) << "Failed to decrypt file with provided token.\n" << Theme::instance().color(Theme::RESET);
            return 1;
        }
        return 0;
    }

    // This block should ideally not be reached if all commands are correctly handled.
    // It acts as a final catch-all for any missed command handling, but should be rare.
    std::cerr << Theme::instance().color(Theme::ERROR) << I18n::instance().t("common.error_unrecognized_command", {{"cmd", arg1}}) << Theme::instance().color(Theme::RESET) << "\n";
    UI::print_usage();
    return 1;
}
