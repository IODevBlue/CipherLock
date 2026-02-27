#include "Vault.hpp"
#include "I18n.hpp"
#include "Theme.hpp"
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <nlohmann/json.hpp>
#include <iomanip>

using json = nlohmann::json;

Vault::Vault() : is_armed(false) {} // TODO: Test this method (Gemini)

void Vault::derive_master_key(const std::string& password, const unsigned char* salt, unsigned char* key) { // TODO: Test this method (Gemini)
    // Using 600,000 iterations and SHA-256 for 2026 security standards
    PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt, SALT_LEN, 600000, EVP_sha256(), 32, key);
}

void Vault::derive_file_key(const unsigned char* master_key, const unsigned char* file_id, unsigned char* file_key) { // TODO: Test this method (Gemini)
    unsigned int len = 32;
    HMAC(EVP_sha256(), master_key, 32, file_id, FILE_ID_LEN, file_key, &len);
}

void Vault::display_laser_grid() const { // TODO: Test this method (Gemini)
    // ... (rest of display_laser_grid remains the same)
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
        std::cout << "\n" << I18n::instance().t("vault.laser_grid") << "\n";
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
    
    // Ensure essential files exist even on load
    fs::path ignore_file = vault_root / ".cipherignore";
    if (!fs::exists(ignore_file)) {
        std::ofstream out(ignore_file);
        out << ".git/\n.cipherlock/\n.DS_Store\nnode_modules/\nbuild/\n";
    }

    ensure_gitignore_ignored();

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

bool Vault::is_initialized() const { // TODO: Test this method (Gemini)
    return fs::exists(vault_root / ".cipherlock" / "config.json");
}

std::string Vault::get_root() const { // TODO: Test this method (Gemini)
    return vault_root.string();
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
        std::cout << Theme::instance().color(Theme::SECONDARY) << I18n::instance().t("vault.reinitialized", {{"path", vault_root.string()}}) << Theme::instance().color(Theme::RESET) << std::endl;
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
        std::cout << I18n::instance().t("vault.created_ignore") << std::endl;
    }

    // 2. Add .cipherlock to .gitignore
    ensure_gitignore_ignored();

    // 3. Generate TOTP Secret
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
    
    std::cout << Theme::instance().color(Theme::SUCCESS) << I18n::instance().t("vault.initialized", {{"path", vault_root.string()}}) << Theme::instance().color(Theme::RESET) << std::endl;
    std::cout << Theme::instance().color(Theme::SECONDARY) << I18n::instance().t("vault.totp_secret", {{"secret", base32_secret}}) << Theme::instance().color(Theme::RESET) << std::endl;
    std::cout << I18n::instance().t("vault.save_secret_warning") << std::endl;
    
    return true;
}

void Vault::ensure_gitignore_ignored() { // TODO: Test this method (Gemini)
    fs::path gitignore_file = vault_root / ".gitignore";
    bool already_ignored = false;
    
    if (fs::exists(gitignore_file)) {
        std::ifstream in(gitignore_file);
        std::string line;
        while (std::getline(in, line)) {
            // Trim line
            line.erase(0, line.find_first_not_of(" \t\n\r\f\v"));
            line.erase(line.find_last_not_of(" \t\n\r\f\v") + 1);
            
            if (line == ".cipherlock" || line == ".cipherlock/" || line == "/.cipherlock/" || line == "/.cipherlock") {
                already_ignored = true;
                break;
            }
        }
    }

    if (!already_ignored) {
        std::ofstream out(gitignore_file, std::ios::app);
        if (out) {
            out << "\n# Cipherlock\n.cipherlock/\n";
            std::cout << I18n::instance().t("vault.gitignore_updated") << std::endl;
        } else {
            std::cerr << I18n::instance().t("vault.gitignore_error") << std::endl;
        }
    }
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

bool Vault::should_ignore(const fs::path& path, const std::vector<std::regex>& root_patterns) { // TODO: Test this method (modified by Gemini)
    std::string rel_path = fs::relative(path, vault_root).string();
    
    // 1. Check root patterns
    for (const auto& pattern : root_patterns) {
        if (std::regex_match(rel_path, pattern) || std::regex_search(rel_path, pattern)) {
            return true;
        }
    }

    // 2. Check for local .cipherignore in all parent directories up to vault_root
    fs::path current = path.parent_path();
    while (true) {
        fs::path local_ignore = current / ".cipherignore";
        if (fs::exists(local_ignore)) {
            std::ifstream file(local_ignore);
            std::string line;
            while (std::getline(file, line)) {
                line.erase(0, line.find_first_not_of(" \t\n\r\f\v"));
                line.erase(line.find_last_not_of(" \t\n\r\f\v") + 1);

                if (!line.empty() && line[0] != '#') {
                    std::string pattern_str = line;
                    // Basic glob to regex conversion (simplified)
                    size_t pos = 0;
                    while ((pos = pattern_str.find(".", pos)) != std::string::npos) {
                        pattern_str.replace(pos, 1, "\\.");
                        pos += 2;
                    }
                    pos = 0;
                    while ((pos = pattern_str.find("*", pos)) != std::string::npos) {
                        pattern_str.replace(pos, 1, ".*");
                        pos += 2;
                    }
                    
                    try {
                        std::regex pattern(pattern_str);
                        // Check if the filename or relative path matches
                        if (std::regex_match(path.filename().string(), pattern) || 
                            std::regex_search(path.filename().string(), pattern)) {
                            return true;
                        }
                    } catch (...) {}
                }
            }
        }
        if (current == vault_root) break;
        current = current.parent_path();
        if (current.string().length() < vault_root.string().length()) break;
    }

    return false;
}

bool Vault::encrypt_file(const fs::path& filepath, const std::string& password) { // TODO: Test this method (Gemini)
    std::ifstream in(filepath, std::ios::binary);
    if (!in) return false;

    FileHeader header;
    memcpy(header.magic, MAGIC, 4);
    header.version = VERSION;
    
    // Generate File ID from relative path hash
    std::string rel_path = fs::relative(filepath, vault_root).string();
    unsigned int id_len = 16;
    EVP_Digest((unsigned char*)rel_path.c_str(), rel_path.length(), header.file_id, &id_len, EVP_md5(), NULL);

    RAND_bytes(header.salt, SALT_LEN);
    RAND_bytes(header.iv, IV_LEN);

    unsigned char master_key[32];
    derive_master_key(password, header.salt, master_key);

    unsigned char file_key[32];
    derive_file_key(master_key, header.file_id, file_key);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, file_key, header.iv);

    std::string out_path = filepath.string() + ".tmp";
    std::ofstream out(out_path, std::ios::binary);
    out.write((char*)&header, sizeof(FileHeader));

    unsigned char in_buf[4096];
    unsigned char out_buf[4096 + 16];
    int out_len;

    while (in.read((char*)in_buf, sizeof(in_buf)) || in.gcount() > 0) {
        if (EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, (int)in.gcount()) <= 0) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        out.write((char*)out_buf, out_len);
    }

    if (EVP_EncryptFinal_ex(ctx, out_buf, &out_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    out.write((char*)out_buf, out_len);

    EVP_CIPHER_CTX_free(ctx);
    in.close();
    out.close();

    fs::remove(filepath);
    fs::rename(out_path, filepath.string() + ".locked");
    return true;
}

bool Vault::decrypt_file(const fs::path& filepath, const std::string& password) { // TODO: Test this method (Gemini)
    std::ifstream in(filepath, std::ios::binary);
    if (!in) return false;

    FileHeader header;
    in.read((char*)&header, sizeof(FileHeader));
    if (memcmp(header.magic, MAGIC, 4) != 0) return false;

    unsigned char master_key[32];
    derive_master_key(password, header.salt, master_key);

    unsigned char file_key[32];
    derive_file_key(master_key, header.file_id, file_key);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, file_key, header.iv);

    std::string original_path = filepath.string();
    original_path = original_path.substr(0, original_path.find(".locked"));
    std::string out_path = original_path + ".tmp";
    std::ofstream out(out_path, std::ios::binary);

    unsigned char in_buf[4096];
    unsigned char out_buf[4096 + 16];
    int out_len;

    while (in.read((char*)in_buf, sizeof(in_buf)) || in.gcount() > 0) {
        if (EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, (int)in.gcount()) <= 0) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        out.write((char*)out_buf, out_len);
    }

    if (EVP_DecryptFinal_ex(ctx, out_buf, &out_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    out.write((char*)out_buf, out_len);

    EVP_CIPHER_CTX_free(ctx);
    in.close();
    out.close();

    fs::remove(filepath);
    fs::rename(out_path, original_path);
    return true;
}

std::string Vault::share_file(const fs::path& filepath, const std::string& password) { // TODO: Test this method (Gemini)
    if (!fs::exists(filepath)) return "";
    
    std::ifstream in(filepath, std::ios::binary);
    if (!in) return "";

    FileHeader header;
    in.read((char*)&header, sizeof(FileHeader));
    if (memcmp(header.magic, MAGIC, 4) != 0) return "";
    in.close();

    unsigned char master_key[32];
    derive_master_key(password, header.salt, master_key);

    unsigned char file_key[32];
    derive_file_key(master_key, header.file_id, file_key);

    // Convert keys/IDs to hex for JSON
    auto to_hex = [](const unsigned char* data, size_t len) {
        std::stringstream ss;
        for(size_t i=0; i<len; ++i) ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
        return ss.str();
    };

    json token;
    token["fileID"] = to_hex(header.file_id, FILE_ID_LEN);
    token["key"] = to_hex(file_key, 32);
    token["fileName"] = filepath.filename().string();
    
    return token.dump(4);
}

bool Vault::decrypt_with_token(const std::string& token_json, const std::string& directory) { // TODO: Test this method (Gemini)
    try {
        json token = json::parse(token_json);
        std::string target_id_hex = token.at("fileID").get<std::string>();
        std::string key_hex = token.at("key").get<std::string>();

        auto from_hex = [](const std::string& hex, unsigned char* out) {
            for (size_t i = 0; i < hex.length(); i += 2) {
                out[i / 2] = std::stoi(hex.substr(i, 2), nullptr, 16);
            }
        };

        unsigned char file_key[32];
        from_hex(key_hex, file_key);

        // Scan directory for file with matching ID
        for (const auto& entry : fs::recursive_directory_iterator(directory)) {
            if (entry.is_regular_file() && entry.path().extension() == ".locked") {
                std::ifstream in(entry.path(), std::ios::binary);
                FileHeader header;
                in.read((char*)&header, sizeof(FileHeader));
                in.close();

                std::stringstream ss;
                for(size_t i=0; i<FILE_ID_LEN; ++i) ss << std::hex << std::setw(2) << std::setfill('0') << (int)header.file_id[i];
                
                if (ss.str() == target_id_hex) {
                    // Found it! Decrypt.
                    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, file_key, header.iv);

                    std::string original_path = entry.path().string();
                    original_path = original_path.substr(0, original_path.find(".locked"));
                    std::string out_path = original_path + ".tmp";
                    std::ofstream out(out_path, std::ios::binary);

                    std::ifstream in2(entry.path(), std::ios::binary);
                    in2.seekg(sizeof(FileHeader));

                    unsigned char in_buf[4096];
                    unsigned char out_buf[4096 + 16];
                    int out_len;

                    while (in2.read((char*)in_buf, sizeof(in_buf)) || in2.gcount() > 0) {
                        if (EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, (int)in2.gcount()) <= 0) {
                            EVP_CIPHER_CTX_free(ctx);
                            return false;
                        }
                        out.write((char*)out_buf, out_len);
                    }

                    if (EVP_DecryptFinal_ex(ctx, out_buf, &out_len) <= 0) {
                        EVP_CIPHER_CTX_free(ctx);
                        return false;
                    }
                    out.write((char*)out_buf, out_len);

                    EVP_CIPHER_CTX_free(ctx);
                    in2.close();
                    out.close();

                    fs::remove(entry.path());
                    fs::rename(out_path, original_path);
                    return true;
                }
            }
        }
    } catch (...) {
        return false;
    }
    return false;
}


bool Vault::lock_vault(const std::string& password) { // TODO: Test this method (modified by Gemini)
    display_laser_grid();
    auto patterns = read_ignore_patterns();
    int count = 0;
    for (const auto& entry : fs::recursive_directory_iterator(vault_root)) {
        if (entry.is_regular_file() && !should_ignore(entry.path(), patterns)) {
            if (encrypt_file(entry.path(), password)) {
                count++;
                std::cout << Theme::instance().color(Theme::SECONDARY) << I18n::instance().t("vault.locked", {{"path", fs::relative(entry.path(), vault_root).string()}}) << Theme::instance().color(Theme::RESET) << std::endl;
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

    std::cout << "\n" << Theme::instance().color(Theme::SUCCESS) << I18n::instance().t("vault.armed_success", {{"count", std::to_string(count)}}) << Theme::instance().color(Theme::RESET) << std::endl;
    return true;
}

bool Vault::unlock_vault(const std::string& password) { // TODO: Test this method (modified by Gemini)
    auto patterns = read_ignore_patterns();
    int count = 0;
    for (const auto& entry : fs::recursive_directory_iterator(vault_root)) {
        if (entry.is_regular_file() && entry.path().extension() == ".locked") {
            if (decrypt_file(entry.path(), password)) {
                count++;
                std::cout << Theme::instance().color(Theme::SUCCESS) << I18n::instance().t("vault.unlocked", {{"path", fs::relative(entry.path(), vault_root).string()}}) << Theme::instance().color(Theme::RESET) << std::endl;
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

    std::cout << "\n" << Theme::instance().color(Theme::SUCCESS) << I18n::instance().t("vault.disarmed_success", {{"count", std::to_string(count)}}) << Theme::instance().color(Theme::RESET) << std::endl;
    return true;
}

void Vault::display_status() const { // TODO: Test this method (modified by Gemini)
    std::string status = is_armed ? "ARMED 🔒" : "DISARMED 🔓";
    std::cout << "\n" << Theme::instance().color(Theme::SECONDARY) << I18n::instance().t("vault.status", {{"status", status}}) << Theme::instance().color(Theme::RESET) << std::endl;
    std::cout << I18n::instance().t("vault.location", {{"path", vault_root.string()}}) << std::endl;
}
