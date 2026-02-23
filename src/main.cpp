#include "Vault.hpp"
#include "TOTP.hpp"
#include "UI.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

const std::string CIPHERLOCK_VERSION = "1.0.0";

void display_version() { // TODO: Test this method (Gemini)
    std::cout << "CipherLock version " << CIPHERLOCK_VERSION << std::endl;
}

void run_hot_mode() { // TODO: Test this method (Gemini)
    Vault vault;
    TOTP totp("Sup3rS3cr3tK3y!"); // Default for now
    
    std::cout << "\033[1;32m🚀 CipherLock 9000 - Hot Mode Active\033[0m\n";
    
    while (true) {
        std::cout << "\n\033[1;36m[1] Setup | [2] Arm | [3] Disarm | [4] TOTP | [5] Status | [6] Exit\033[0m\n";
        std::cout << "Selection: ";
        int choice;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(1000, '\n');
            continue;
        }

        if (choice == 6) break;

        switch (choice) {
            case 1: {
                std::cout << "Path: ";
                std::string dir;
                std::cin >> dir;
                vault.setup(dir);
                break;
            }
            case 2: {
                std::cout << "Password: ";
                std::string pwd;
                std::cin >> pwd;
                vault.arm(pwd);
                break;
            }
            case 3: {
                std::cout << "TOTP: ";
                std::string code;
                std::cin >> code;
                if (totp.verify(code)) {
                    std::cout << "Password: ";
                    std::string pwd;
                    std::cin >> pwd;
                    vault.disarm(pwd);
                } else {
                    std::cout << "\033[1;31m❌ Invalid TOTP\033[0m\n";
                }
                break;
            }
            case 4:
                std::cout << "🔑 \033[1;33mTOTP: " << totp.generate_current() << "\033[0m (" << totp.get_seconds_remaining() << "s)\n";
                break;
            case 5:
                vault.display_status();
                break;
            default:
                std::cout << "Invalid Option\n";
        }
    }
}

void run_cold_mode(const std::string& src, const std::string& key_file, const std::string& dest) { // TODO: Test this method (Gemini)
    std::cout << "❄️ CipherLock 9000 - Cold Mode Initialized\n";
    
    std::ifstream kf(key_file);
    if (!kf) {
        std::cerr << "\033[1;31m❌ Error: Cannot open key file: " << key_file << "\033[0m\n";
        return;
    }
    std::string key;
    std::getline(kf, key);
    
    Vault vault;
    if (vault.setup(src)) {
        std::cout << "Arming vault...\n";
        vault.arm(key);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        UI::print_welcome(CIPHERLOCK_VERSION);
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

    if (arg1 == "init") {
        std::string target_dir = (argc >= 3) ? argv[2] : ".";
        Vault vault;
        if (!vault.setup(target_dir)) {
            std::cerr << "\033[1;31m❌ Error: Failed to initialize vault in '" << target_dir << "'. Check permissions.\033[0m\n";
            return 1;
        }
        return 0;
    }

    if (arg1 == "arm") {
        std::string target_dir = (argc >= 3) ? argv[2] : ".";
        Vault vault;
        if (!vault.load(target_dir)) {
            std::cerr << "\033[1;31m❌ Error: No vault found in '" << target_dir << "'. Run 'init' first.\033[0m\n";
            return 1;
        }
        
        std::cout << "Enter encryption password: ";
        std::string password;
        std::cin >> password;
        vault.arm(password);
        return 0;
    }

    if (arg1 == "disarm") {
        std::string target_dir = (argc >= 3) ? argv[2] : ".";
        Vault vault;
        if (!vault.load(target_dir)) {
            std::cerr << "\033[1;31m❌ Error: No vault found in '" << target_dir << "'. Run 'init' first.\033[0m\n";
            return 1;
        }

        std::string secret = vault.get_totp_secret();
        if (secret.empty()) {
            std::cerr << "\033[1;31m❌ Error: Could not read TOTP secret from config.\033[0m\n";
            return 1;
        }

        TOTP totp(secret, true); // Use Base32 decoding
        std::cout << "Enter TOTP code: ";
        std::string code;
        std::cin >> code;

        if (totp.verify(code)) {
            std::cout << "Enter decryption password: ";
            std::string password;
            std::cin >> password;
            vault.disarm(password);
        } else {
            std::cerr << "\033[1;31m❌ Invalid TOTP code!\033[0m\n";
            return 1;
        }
        return 0;
    }

    std::cerr << "\033[1;31m❌ Error: Unrecognized command: '" << arg1 << "'\033[0m\n";
    UI::print_usage();
    return 1;
}
