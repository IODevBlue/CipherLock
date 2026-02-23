#include "Vault.hpp"
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

Vault::Vault() : is_armed(false) {} // TODO: Test this method (Gemini)

void Vault::display_laser_grid() const { // TODO: Test this method (Gemini)
    // TODO: Test this animation and see what it looks like
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
        // Clear screen logic removed for CLI friendliness
        // #ifdef _WIN32
        //     system("cls");
        // #else
        //     system("clear");
        // #endif
        std::cout << "\n🚨 LASER DEFENSE GRID ACTIVE 🚨\n";
        for (const auto& line : frames) {
            std::cout << line << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        std::swap(frames[1], frames[5]);
    }
}

bool Vault::load(const std::string& directory) { // TODO: Test this method (Gemini)
    vault_root = fs::absolute(directory);
    fs::path config_path = vault_root / ".cipherlock" / "config.json";
    
    if (!fs::exists(config_path)) {
        return false;
    }
    
    std::ifstream config_file(config_path);
    if (!config_file) return false;
    
    json config;
    try {
        // Use the config JSON to load stuffs into memory
        config_file >> config;
        is_armed = config.value("armed", false);
    } catch (...) {
        return false;
    }
    
    return true;
}

std::string Vault::get_totp_secret() { // TODO: Test this method (Gemini)
    fs::path config_path = vault_root / ".cipherlock" / "config.json";
    if (!fs::exists(config_path)) return "";
    
    std::ifstream config_file(config_path);
    if (!config_file) return "";
    
    try {
        json config;
        config_file >> config;
        return config.value("totp_secret", "");
    } catch (...) {
        return "";
    }
}

bool Vault::setup(const std::string& directory) { // TODO: Test this method (modified by Gemini)
    fs::path p = fs::absolute(directory);
    if (!fs::exists(p)) {
        fs::create_directories(p);
    }
    vault_root = fs::canonical(p);
    
    fs::path config_dir = vault_root / ".cipherlock";
    fs::path config_file_path = config_dir / "config.json";

    if (fs::exists(config_dir) && fs::exists(config_file_path)) {
        std::cout << "\033[1;33m🔄 Reinitialized existing Vault at: " << vault_root.string() << "\033[0m" << std::endl;
        return true;
    }
    
    if (!fs::exists(config_dir)) {
        fs::create_directories(config_dir);
    }

    // 1. Create default .cipherignore if not exists
    fs::path ignore_file = vault_root / ".cipherignore";
    if (!fs::exists(ignore_file)) {
        std::ofstream out(ignore_file);
        out << ".git/\n.cipherlock/\n.DS_Store\nnode_modules/\nbuild/\n";
        std::cout << "📝 Created default .cipherignore\n";
    }

    // 2. Generate TOTP Secret
    unsigned char rnd_key[20];
    RAND_bytes(rnd_key, 20);
    std::string secret(reinterpret_cast<char*>(rnd_key), 20);
    
    // Convert to Base32 for display/storage
    // (Simple Base32 implementation for config)
    const char* base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string base32_secret;
    int buffer = 0, bits_left = 0;
    for (unsigned char byte : rnd_key) {
        buffer = (buffer << 8) | byte;
        bits_left += 8;
        while (bits_left >= 5) {
            bits_left -= 5;
            base32_secret += base32_chars[(buffer >> bits_left) & 0x1F];
        }
    }
    if (bits_left > 0) base32_secret += base32_chars[(buffer << (5 - bits_left)) & 0x1F];

    json config;
    config["armed"] = false;
    config["setup_date"] = std::chrono::system_clock::now().time_since_epoch().count();
    config["totp_secret"] = base32_secret; // Store base32 for ease of use
    
    std::ofstream config_file(config_file_path);
    if (!config_file) return false;
    config_file << config.dump(4);
    
    std::cout << "\033[1;32m🔧 Vault initialized at: " << vault_root.string() << "\033[0m" << std::endl;
    std::cout << "\033[1;33m🔑 TOTP SECRET: " << base32_secret << "\033[0m" << std::endl;
    std::cout << "⚠️  Save this secret! You will need it to generate codes." << std::endl;
    
    return true;
}

std::vector<std::regex> Vault::read_ignore_patterns() { // TODO: Test this method (Gemini)
    std::vector<std::regex> patterns;
    fs::path ignore_file = vault_root / ".cipherignore";
    
    if (!fs::exists(ignore_file)) {
        ignore_file = vault_root / ".gitignore";
    }
    
    if (fs::exists(ignore_file)) {
        std::ifstream file(ignore_file);
        std::string line;
        while (std::getline(file, line)) {
            // Trim leading/trailing whitespace including \r
            line.erase(0, line.find_first_not_of(" \t\n\r\f\v"));
            line.erase(line.find_last_not_of(" \t\n\r\f\v") + 1);

            if (!line.empty() && line[0] != '#') {
                std::string pattern = line;
                // Basic conversion of glob to regex
                size_t pos = 0;
                while ((pos = pattern.find(".", pos)) != std::string::npos) {
                    pattern.replace(pos, 1, "\\.");
                    pos += 2;
                }
                pos = 0;
                while ((pos = pattern.find("*", pos)) != std::string::npos) {
                    pattern.replace(pos, 1, ".*");
                    pos += 2;
                }
                patterns.push_back(std::regex(pattern));
            }
        }
    }
    
    patterns.push_back(std::regex("\\.cipherlock/.*"));
    patterns.push_back(std::regex("\\.git/.*"));
    return patterns;
}

bool Vault::should_ignore(const fs::path& path, const std::vector<std::regex>& patterns) { // TODO: Test this method (Gemini)
    std::string rel_path = fs::relative(path, vault_root).string();
    for (const auto& pattern : patterns) {
        if (std::regex_match(rel_path, pattern) || std::regex_search(rel_path, pattern)) {
            return true;
        }
    }
    return false;
}

bool Vault::encrypt_file(const fs::path& filepath, const std::string& password) { // TODO: Test this method (Gemini)
    std::ifstream in(filepath, std::ios::binary);
    if (!in) return false;
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    unsigned char iv[16];
    RAND_bytes(iv, 16);

    unsigned char key[32];
    PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.length(), iv, 8, 10000, 32, key);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    std::vector<unsigned char> ciphertext(content.length() + 16);
    int len = 0, ciphertext_len = 0;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)content.c_str(), content.length());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    std::ofstream out(filepath, std::ios::binary);
    out.write((char*)iv, 16);
    out.write((char*)ciphertext.data(), ciphertext_len);
    out.close();

    fs::rename(filepath, filepath.string() + ".locked");
    return true;
}

bool Vault::decrypt_file(const fs::path& filepath, const std::string& password) { // TODO: Test this method (Gemini)
    std::ifstream in(filepath, std::ios::binary);
    if (!in) return false;

    unsigned char iv[16];
    in.read((char*)iv, 16);

    std::string ciphertext((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    unsigned char key[32];
    PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.length(), iv, 8, 10000, 32, key);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    std::vector<unsigned char> plaintext(ciphertext.length() + 16);
    int len = 0, plaintext_len = 0;
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, (unsigned char*)ciphertext.data(), ciphertext.length());
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    std::string original_path = filepath.string();
    original_path = original_path.substr(0, original_path.find(".locked"));

    std::ofstream out(original_path, std::ios::binary);
    out.write((char*)plaintext.data(), plaintext_len);
    out.close();

    fs::remove(filepath);
    return true;
}

bool Vault::arm(const std::string& password) { // TODO: Test this method (Gemini)
    display_laser_grid();
    auto patterns = read_ignore_patterns();
    int count = 0;
    for (const auto& entry : fs::recursive_directory_iterator(vault_root)) {
        if (entry.is_regular_file() && !should_ignore(entry.path(), patterns)) {
            if (encrypt_file(entry.path(), password)) {
                count++;
                std::cout << "🔒 Locked: " << fs::relative(entry.path(), vault_root) << std::endl;
            }
        }
    }
    is_armed = true;

    // Update config
    json config;
    config["armed"] = true;
    config["encryption_date"] = std::chrono::system_clock::now().time_since_epoch().count();
    config["files_encrypted"] = count;
    std::ofstream config_file(vault_root / ".cipherlock" / "config.json");
    config_file << config.dump(4);

    std::cout << "\n\033[1;32m✅ VAULT ARMED: " << count << " files encrypted\033[0m" << std::endl;
    return true;
}

bool Vault::disarm(const std::string& password) { // TODO: Test this method (Gemini)
    auto patterns = read_ignore_patterns();
    int count = 0;
    for (const auto& entry : fs::recursive_directory_iterator(vault_root)) {
        if (entry.is_regular_file() && entry.path().extension() == ".locked") {
            if (decrypt_file(entry.path(), password)) {
                count++;
                std::cout << "🔓 Unlocked: " << fs::relative(entry.path(), vault_root) << std::endl;
            }
        }
    }
    is_armed = false;

    // Update config
    json config;
    config["armed"] = false;
    config["disarm_date"] = std::chrono::system_clock::now().time_since_epoch().count();
    std::ofstream config_file(vault_root / ".cipherlock" / "config.json");
    config_file << config.dump(4);

    std::cout << "\n\033[1;32m✅ VAULT DISARMED: " << count << " files restored\033[0m" << std::endl;
    return true;
}

void Vault::display_status() const { // TODO: Test this method (Gemini)
    std::cout << "\n📊 Vault Status: " << (is_armed ? "ARMED 🔒" : "DISARMED 🔓") << std::endl;
    std::cout << "📍 Location: " << vault_root << std::endl;
}
