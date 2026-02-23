#include "Vault.hpp"
#include "TOTP.hpp"
#include "UI.hpp"
#include "I18n.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

// TODO: Extract the raw strings here to the localized jsons

const std::string CIPHERLOCK_VERSION = "1.0.0";

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
                    std::cout << I18n::instance().t("settings.lang_change_failed", {{"lang", lang_code}}) << std::endl;
                }
                break;
            }
            case 2: { // List Languages
                std::cout << I18n::instance().t("settings.available_languages") << std::endl;
                for (const auto& lang : I18n::instance().getAvailableLanguages("../locales")) {
                    std::cout << "- " << lang << std::endl;
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

void run_hot_mode() { // TODO: Test this method (modified by Gemini)
    Vault vault;
    // TODO: Change the super secret key to something else and then include it in the config.json
    TOTP totp("Sup3rS3cr3tK3y!"); // Default for now
    
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
    std::cout << "❄️ " << I18n::instance().t("ui.cold_mode_active", {{"version", CIPHERLOCK_VERSION}}) << "\n";
    
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

    if (argc < 2) {
        UI::print_welcome(CIPHERLOCK_VERSION, I18n::instance().getLanguageName());
        UI::print_usage();
        return 0;
    }

    std::string arg1 = argv[1];

    if (arg1 == "--help" || arg1 == "-h") {
        UI::print_usage();
        return 0;
    }

    if (arg1 == "--version" || arg1 == "-v") {
        display_version();
        return 0;
    }

    if (arg1 == "boot") {
        run_hot_mode();
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

    std::cerr << I18n::instance().t("common.error_unrecognized_command", {{"cmd", arg1}}) << "\n";
    UI::print_usage();
    return 1;
}
