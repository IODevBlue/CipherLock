#include "Vault.hpp"
#include "I18n.hpp"
#include "Theme.hpp"
#include "ProfileManager.hpp"
#include "SignatureEngine.hpp"
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

void Vault::ConflictReport::save_to_file(const fs::path& path) const { // TODO: Test this method (Gemini)
    std::ofstream ofs(path);
    if (!ofs) return;
    ofs << I18n::instance().t("signature.report_header") << "\n";
    std::time_t now_c = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::string date_str = std::ctime(&now_c);
    if (!date_str.empty()) date_str.pop_back();
    ofs << I18n::instance().t("signature.report_generated_on", {{"date", date_str}}) << "\n\n";
    ofs << I18n::instance().t("signature.report_skipped_files") << "\n";
    for (const auto& file : conflicted_files) {
        ofs << " - " << file.string() << "\n";
    }
}

void Vault::ConflictReport::print_summary() const { // TODO: Test this method (Gemini)
    if (conflicted_files.empty()) return;

    std::cout << Theme::instance().color(Theme::WARNING) << I18n::instance().t("signature.conflict_summary", {{"count", std::to_string(conflicted_files.size())}}) << Theme::instance().color(Theme::RESET) << "\n";
    size_t show_count = std::min(conflicted_files.size(), (size_t)5);
    for (size_t i = 0; i < show_count; ++i) {
        std::cout << "  - " << conflicted_files[i].filename().string() << "\n";
    }
    if (conflicted_files.size() > 5) {
        std::cout << I18n::instance().t("signature.conflict_more", {{"count", std::to_string(conflicted_files.size() - 5)}}) << "\n";
    }
    std::cout << I18n::instance().t("signature.conflict_save_notice") << "\n";
}

Vault::Vault() : is_armed(false) {} // TODO: Test this method (Gemini)

void Vault::derive_file_key(const unsigned char* key, const unsigned char* file_id, unsigned char* file_key) { // TODO: Test this method (Gemini)
    unsigned int len = 32;
    HMAC(EVP_sha256(), key, 32, file_id, FILE_ID_LEN, file_key, &len);
}

void Vault::derive_milestone_key(const unsigned char* master_key, const unsigned char* milestone_id, unsigned char* milestone_key) { // TODO: Test this method (Gemini)
    unsigned int len = 32;
    HMAC(EVP_sha256(), master_key, 32, milestone_id, FILE_ID_LEN, milestone_key, &len);
}

void Vault::uuid_to_bytes(const std::string& uuid, unsigned char* bytes) { // TODO: Test this method (Gemini)
    std::string hex = uuid;
    hex.erase(std::remove(hex.begin(), hex.end(), '-'), hex.end());
    for (size_t i = 0; i < 16; ++i) {
        bytes[i] = static_cast<unsigned char>(std::stoi(hex.substr(i * 2, 2), nullptr, 16));
    }
}

std::string Vault::bytes_to_uuid(const unsigned char* bytes) { // TODO: Test this method (Gemini)
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 16; ++i) {
        ss << std::setw(2) << (int)bytes[i];
        if (i == 3 || i == 5 || i == 7 || i == 9) ss << "-";
    }
    return ss.str();
}

std::string Vault::generate_uuid() { // TODO: Test this method (Gemini)
    unsigned char buf[16];
    RAND_bytes(buf, 16);
    
    // Set version to 4 (random)
    buf[6] = (buf[6] & 0x0f) | 0x40;
    // Set variant to RFC 4122
    buf[8] = (buf[8] & 0x3f) | 0x80;

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 16; ++i) {
        ss << std::setw(2) << (int)buf[i];
        if (i == 3 || i == 5 || i == 7 || i == 9) ss << "-";
    }
    return ss.str();
}

bool Vault::load_master_key() { // TODO: Test this method (Gemini)
    fs::path key_path = vault_root / ".cipherlock" / "keys" / "master.clkey";
    std::string key_json_str;

    if (fs::exists(key_path)) {
        std::ifstream ifs(key_path);
        key_json_str = std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    } else {
        // Try to restore from profile backup
        key_json_str = cipherLock::ProfileManager::getProjectKeyBackup(active_profile_name, project_uuid);
        if (!key_json_str.empty()) {
            std::cout << Theme::instance().color(Theme::INFO) << I18n::instance().t("signature.restoring_key") << Theme::instance().color(Theme::RESET) << std::endl;
            fs::create_directories(vault_root / ".cipherlock" / "keys");
            std::ofstream ofs(key_path);
            ofs << key_json_str;
        }
    }

    if (key_json_str.empty()) return false;

    try {
        json key_json = json::parse(key_json_str);
        if (key_json["project_uuid"] != project_uuid) {
            return false;
        }

        std::string hex_key = key_json["key_payload"];
        master_key.clear();
        for (size_t i = 0; i < hex_key.length(); i += 2) {
            master_key.push_back(static_cast<unsigned char>(std::stoi(hex_key.substr(i, 2), nullptr, 16)));
        }
        return true;
    } catch (...) {
        return false;
    }
}

bool Vault::save_master_key() { // TODO: Test this method (Gemini)
    if (master_key.empty()) {
        master_key.resize(32);
        RAND_bytes(master_key.data(), 32);
    }

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char b : master_key) ss << std::setw(2) << (int)b;
    std::string hex_key = ss.str();

    json key_json;
    key_json["project_uuid"] = project_uuid;
    key_json["created_by"] = active_profile_name;
    key_json["created_at"] = std::chrono::system_clock::now().time_since_epoch().count();
    key_json["key_payload"] = hex_key;

    std::string key_str = key_json.dump(4);
    
    fs::path key_dir = vault_root / ".cipherlock" / "keys";
    fs::create_directories(key_dir);
    
    std::ofstream ofs(key_dir / "master.clkey");
    if (!ofs) return false;
    ofs << key_str;
    ofs.close();

    // Backup to profile
    cipherLock::ProfileManager::backupProjectKey(active_profile_name, project_uuid, key_str);
    
    return true;
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
        // TODO: Template based approach for the cipherignore.
        std::ofstream out(ignore_file);
        out << ".git/\n.cipherlock/\n.DS_Store\nnode_modules/\nbuild/\n";
    }

    // Ensure signature config files exist
    fs::path signature_yaml_path = vault_root / ".cipherlock" / "file_signature.yaml";
    if (!fs::exists(signature_yaml_path)) {
        std::ofstream out(signature_yaml_path);
        out << "header:\n"
            << "  template_path: \".cipherlock/signature_header.txt\"\n" // Updated path
            << "  comment_style: \"auto\"\n"
            << "  enforce_visibility: true\n";
    }

    fs::path signature_header_template_path = vault_root / ".cipherlock" / "signature_header.txt"; // Updated file name
    if (!fs::exists(signature_header_template_path)) {
        std::ofstream out(signature_header_template_path);
        out << I18n::instance().t("signature.default_header_title") << "\n"
            << I18n::instance().t("signature.default_header_project_id") << "\n"
            << I18n::instance().t("signature.default_header_locked_by") << "\n"
            << I18n::instance().t("signature.default_header_date") << "\n\n"
            << I18n::instance().t("signature.default_header_contacts_title") << "\n"
            << I18n::instance().t("signature.default_header_contacts_placeholder") << "\n\n"
            << I18n::instance().t("signature.default_header_warning") << "\n"
            << "-------------------------------\n";
    }

    ensure_gitignore_ignored(); // TODO: Test this method (Gemini)

    std::ifstream config_file(config_path);
    if (!config_file) return false;
    
    json config;
    try {
        // Use the config JSON to load stuffs into memory
        config_file >> config;
        is_armed = config.value("armed", false);
        project_uuid = config.value("uuid", "");
        active_profile_name = cipherLock::ProfileManager::getActiveProfileName();
        project_name = config.value("name", "");
        project_description = config.value("description", "");
        project_client = config.value("client", "");
        project_deadline = config.value("deadline", "");
        project_valuation = config.value("valuation", 0.0);
        project_currency = config.value("currency", "USD");
        project_setup_date = config.value("setup_date", (uint64_t)0);
        project_created_by = config.value("created_by", "");
        export_root = config.value("export_root", "cipherlock_export");

        // Ensure export root is ignored
        ensure_gitignore_ignored();
        if (project_uuid.empty()) {
            project_uuid = generate_uuid();
            config["uuid"] = project_uuid;
            std::ofstream out_config(config_path);
            out_config << config.dump(4);
            out_config.close();
        }

        // Try to load master key
        if (!load_master_key()) {
            // Key mismatch or missing. If not armed, we can generate a new one.
            int encrypted_count = config.value("files_encrypted", 0);
            if (encrypted_count == 0) {
                save_master_key();
            } else {
                std::cerr << Theme::instance().color(Theme::ERROR) << "CRITICAL ERROR: Project master key missing or mismatched, but project has encrypted files!" << Theme::instance().color(Theme::RESET) << std::endl;
                return false;
            }
        }

        // If key loaded/restored/generated, but config is missing the pointer, update it
        if (!config.contains("master_key_info")) {
            json key_info;
            key_info["name"] = "master.clkey";
            key_info["location"] = ".cipherlock/keys/master.clkey";
            config["master_key_info"] = key_info;
            std::ofstream out_config(config_path);
            out_config << config.dump(4);
            out_config.close();
        }

        // Load Milestones
        milestones.clear();
        if (config.contains("milestones") && config["milestones"].is_array()) {
            for (const auto& m_json : config["milestones"]) {
                Milestone m;
                m.id = m_json.value("id", "");
                m.name = m_json.value("name", "");
                m.description = m_json.value("description", "");
                m.is_released = m_json.value("is_released", false);
                m.valuation = m_json.value("valuation", 0.0);
                m.currency = m_json.value("currency", "USD");
                m.created_at = m_json.value("created_at", (uint64_t)0);
                m.released_at = m_json.value("released_at", (uint64_t)0);
                milestones.push_back(m);
            }
        }
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

bool Vault::edit_project_metadata() { // TODO: Test this method (Gemini)
    if (!is_initialized()) return false;

    std::cout << "\n" << Theme::instance().color(Theme::PRIMARY) << "--- Edit Project Metadata ---" << Theme::instance().color(Theme::RESET) << "\n";
    std::cout << I18n::instance().t("project.uuid_display", {{"uuid", project_uuid}}) << "\n";

    // 1. Name
    std::cout << I18n::instance().t("project.enter_name", {{"default", project_name}});
    std::string input_name;
    std::getline(std::cin >> std::ws, input_name);
    if (!input_name.empty() && input_name != "q" && input_name != "Q") project_name = input_name;

    // 2. Valuation
    std::cout << I18n::instance().t("project.enter_valuation", {{"default", std::to_string(project_valuation)}});
    std::string input_val;
    std::getline(std::cin, input_val);
    if (!input_val.empty() && input_val != "q" && input_val != "Q") {
        try {
            project_valuation = std::stod(input_val);
        } catch (...) {}
    }

    // 3. Currency
    std::cout << I18n::instance().t("project.enter_currency", {{"default", project_currency}});
    std::string input_curr;
    std::getline(std::cin, input_curr);
    if (!input_curr.empty() && input_curr != "q" && input_curr != "Q") {
        std::transform(input_curr.begin(), input_curr.end(), input_curr.begin(), ::toupper);
        project_currency = input_curr;
    }

    // 4. Description
    std::cout << I18n::instance().t("project.enter_description");
    std::string input_desc;
    std::getline(std::cin, input_desc);
    if (!input_desc.empty() && input_desc != "q" && input_desc != "Q") {
        project_description = input_desc;
    }

    // 5. Client
    std::cout << I18n::instance().t("project.enter_client");
    std::string input_client;
    std::getline(std::cin, input_client);
    if (!input_client.empty() && input_client != "q" && input_client != "Q") {
        project_client = input_client;
    }

    // 6. Deadline
    std::cout << I18n::instance().t("project.enter_deadline");
    std::string input_deadline;
    std::getline(std::cin, input_deadline);
    if (!input_deadline.empty() && input_deadline != "q" && input_deadline != "Q") {
        project_deadline = input_deadline;
    }

    // 7. Export Root
    std::cout << I18n::instance().t("project.enter_export_root", {{"default", export_root.string()}});
    std::string input_export;
    std::getline(std::cin, input_export);
    if (!input_export.empty() && input_export != "q" && input_export != "Q") {
        export_root = input_export;
    }

    save_config();

    std::cout << Theme::instance().color(Theme::SUCCESS) << "\nProject metadata updated successfully.\n" << Theme::instance().color(Theme::RESET);
    display_status();
    return true;
}

bool Vault::setup(const std::string& directory, const std::string& profile_name) { // TODO: Test this method (modified by Gemini)
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

    // 1. Project Metadata
    std::string project_name = vault_root.filename().string();
    double project_valuation = 0.0;
    std::string currency = "USD";

    std::cout << I18n::instance().t("project.enter_name", {{"default", project_name}});
    std::string input_name;
    std::getline(std::cin >> std::ws, input_name);
    if (!input_name.empty() && input_name != "q" && input_name != "Q") {
        project_name = input_name;
    }

    std::cout << I18n::instance().t("project.enter_valuation", {{"default", "0.0"}});
    std::string input_val;
    std::getline(std::cin, input_val);
    if (!input_val.empty() && input_val != "q" && input_val != "Q") {
        try {
            project_valuation = std::stod(input_val);
        } catch (...) {}
    }

    std::cout << I18n::instance().t("project.enter_currency", {{"default", "USD"}});
    std::string input_currency;
    std::getline(std::cin, input_currency);
    if (!input_currency.empty() && input_currency != "q" && input_currency != "Q") {
        std::transform(input_currency.begin(), input_currency.end(), input_currency.begin(), ::toupper);
        currency = input_currency;
    } else {
        std::transform(currency.begin(), currency.end(), currency.begin(), ::toupper);
    }

    std::cout << I18n::instance().t("project.enter_description");
    std::string project_description;
    std::getline(std::cin, project_description);
    if (project_description == "q" || project_description == "Q") project_description = "";

    std::cout << I18n::instance().t("project.enter_client");
    std::string project_client;
    std::getline(std::cin, project_client);
    if (project_client == "q" || project_client == "Q") project_client = "";

    std::cout << I18n::instance().t("project.enter_deadline");
    std::string project_deadline;
    std::getline(std::cin, project_deadline);
    if (project_deadline == "q" || project_deadline == "Q") project_deadline = "";

    std::cout << I18n::instance().t("project.enter_export_root", {{"default", "cipherlock_export"}});
    std::string input_export;
    std::getline(std::cin, input_export);
    export_root = input_export.empty() ? "cipherlock_export" : input_export;

    // 1c. Enhanced Profile Info
    std::string full_name;
    std::cout << I18n::instance().t("profile.enter_full_name");
    std::getline(std::cin, full_name);

    std::vector<cipherLock::UserProfile::Contact> contacts;
    std::cout << I18n::instance().t("profile.add_contacts_hint") << "\n";
    while (true) {
        std::cout << I18n::instance().t("profile.contact_title_prompt");
        std::string title;
        std::getline(std::cin, title);
        if (title.empty() || title == "q") break;

        std::cout << I18n::instance().t("profile.contact_link_prompt");
        std::string link;
        std::getline(std::cin, link);
        if (link == "q") continue; // Skip this entry
        if (link.empty()) link = "nil";

        contacts.push_back({title, link});
    }

    // Update the active profile
    if (!profile_name.empty()) {
        try {
            auto profile = cipherLock::ProfileManager::loadProfile(profile_name);
            profile.full_name = full_name;
            profile.contacts = contacts;
            cipherLock::ProfileManager::saveProfile(profile);
        } catch (...) {}
    }

    // 1d. Create Signature Config and Header Template
    fs::path signature_yaml_path = config_dir / "file_signature.yaml";
    if (!fs::exists(signature_yaml_path)) {
        std::ofstream out(signature_yaml_path);
        out << "header:\n"
            << "  template_path: \".cipherlock/signature_header.txt\"\n" // Updated path
            << "  comment_style: \"auto\"\n"
            << "  enforce_visibility: true\n";
    }

    fs::path signature_header_template_path = config_dir / "signature_header.txt"; // Updated file name
    if (!fs::exists(signature_header_template_path)) {
        std::ofstream out(signature_header_template_path);
        out << I18n::instance().t("signature.default_header_title") << "\n"
            << I18n::instance().t("signature.default_header_project_id") << "\n"
            << I18n::instance().t("signature.default_header_locked_by") << "\n"
            << I18n::instance().t("signature.default_header_date") << "\n\n"
            << I18n::instance().t("signature.default_header_contacts_title") << "\n"
            << I18n::instance().t("signature.default_header_contacts_placeholder") << "\n\n"
            << I18n::instance().t("signature.default_header_warning") << "\n"
            << "-------------------------------\n";
    }

    // 1b. Create default .cipherignore if not exists
    fs::path ignore_file = vault_root / ".cipherignore";
    if (!fs::exists(ignore_file)) {
        std::ofstream out(ignore_file);
        out << ".git/\n.cipherlock/\n.DS_Store\nnode_modules/\nbuild/\n";
        std::cout << I18n::instance().t("vault.created_ignore") << std::endl;
    }

    // 2. Add .cipherlock to .gitignore
    ensure_gitignore_ignored();

    this->project_name = project_name;
    this->project_valuation = project_valuation;
    this->project_currency = currency;
    this->project_description = project_description;
    this->project_client = project_client;
    this->project_deadline = project_deadline;
    this->project_setup_date = std::chrono::system_clock::now().time_since_epoch().count();
    this->project_created_by = profile_name;
    this->active_profile_name = profile_name;
    this->project_uuid = generate_uuid();

    save_master_key();

    save_config();
    
    std::cout << Theme::instance().color(Theme::SUCCESS) << I18n::instance().t("vault.initialized", {{"path", vault_root.string()}}) << Theme::instance().color(Theme::RESET) << std::endl;
    
    return true;
}

void Vault::ensure_gitignore_ignored() { // TODO: Test this method (Gemini)
    auto ensure_ignored = [this](const fs::path& ignore_file_path) {
        bool needs_cipherlock = true;
        bool needs_export = true;
        std::string export_str = export_root.string();
        if (export_str.back() != '/') export_str += "/";

        if (fs::exists(ignore_file_path)) {
            std::ifstream ifs(ignore_file_path);
            std::string line;
            while (std::getline(ifs, line)) {
                line.erase(0, line.find_first_not_of(" \t\n\r\f\v"));
                line.erase(line.find_last_not_of(" \t\n\r\f\v") + 1);

                if (line == ".cipherlock" || line == ".cipherlock/") needs_cipherlock = false;
                if (line == export_str || line == export_root.string()) needs_export = false;
            }
        }

        if (needs_cipherlock || needs_export) {
            std::ofstream ofs(ignore_file_path, std::ios::app);
            if (ofs) {
                if (needs_cipherlock) ofs << "\n# Cipherlock\n.cipherlock/\n";
                if (needs_export) ofs << export_str << "\n";
            }
        }
    };

    ensure_ignored(vault_root / ".gitignore");
    ensure_ignored(vault_root / ".cipherignore");
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

bool Vault::encrypt_file(const fs::path& filepath, const std::string& milestone_id) { // TODO: Test this method (modified by Gemini)
    // 1. Check for Conflict
    {
        std::ifstream peek(filepath, std::ios::binary);
        if (peek) {
            char buf[8192];
            peek.read(buf, sizeof(buf));
            std::string content(buf, peek.gcount());
            
            // Check for Project UUID (plain text) or Magic CLOK
            if (content.find(project_uuid) != std::string::npos || content.find(MAGIC) != std::string::npos) {
                // Conflict detected (already armed)
                return false; 
            }
        }
    }

    std::ifstream in(filepath, std::ios::binary);
    if (!in) return false;

    // 2. Prepare Header V3
    FileHeaderV3 header;
    memcpy(header.magic, MAGIC, 4);
    header.version = VERSION_V3;
    uuid_to_bytes(project_uuid, header.project_uuid);
    
    // Generate File ID from relative path hash
    std::string rel_path = fs::relative(filepath, vault_root).string();
    unsigned int id_len = 16;
    EVP_Digest((unsigned char*)rel_path.c_str(), rel_path.length(), header.file_id, &id_len, EVP_md5(), NULL);

    if (!milestone_id.empty()) {
        uuid_to_bytes(milestone_id, header.milestone_id);
    } else {
        memset(header.milestone_id, 0, FILE_ID_LEN);
    }
    
    header.version_counter = 1;
    RAND_bytes(header.salt, SALT_LEN);
    RAND_bytes(header.iv, IV_LEN);

    // Get payload size
    in.seekg(0, std::ios::end);
    header.payload_size = in.tellg();
    in.seekg(0, std::ios::beg);

    // 3. Prepare Preamble
    std::map<std::string, std::string> vars;
    vars["PROJECT_UUID"] = project_uuid;
    
    try {
        auto profile = cipherLock::ProfileManager::loadProfile(active_profile_name);
        vars["USER_NAME"] = profile.full_name.empty() ? profile.name : profile.full_name;
        
        std::string contact_list;
        for (const auto& c : profile.contacts) {
            contact_list += " - " + c.title + ": " + c.link + "\n";
        }
        vars["CONTACT_LIST"] = contact_list;
    } catch (...) {
        vars["USER_NAME"] = active_profile_name;
        vars["CONTACT_LIST"] = I18n::instance().t("profile.no_contacts_provided");
    }

    std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    vars["DATE"] = std::ctime(&now);
    // Remove newline from ctime
    if (!vars["DATE"].empty()) vars["DATE"].pop_back();

    auto sig_config = cipherLock::SignatureConfig::load(vault_root / ".cipherlock" / "file_signature.yaml");

    std::string preamble = cipherLock::SignatureEngine::generate_preamble(
        filepath, 
        vault_root / sig_config.header.template_path, 
        vars
    );

    // 4. Encrypt
    unsigned char master_key_bytes[32];
    if (master_key.empty()) return false;
    memcpy(master_key_bytes, master_key.data(), 32);

    unsigned char milestone_key[32];
    if (!milestone_id.empty()) {
        derive_milestone_key(master_key_bytes, header.milestone_id, milestone_key);
    } else {
        memcpy(milestone_key, master_key_bytes, 32);
    }
    
    unsigned char file_key[32];
    derive_file_key(milestone_key, header.file_id, file_key);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, file_key, header.iv);

    fs::path rel_filepath = fs::relative(filepath, vault_root);
    fs::path out_path = vault_root / export_root / "locked" / (rel_filepath.string() + ".locked");
    
    // Ensure parent directory exists in export
    fs::create_directories(out_path.parent_path());

    std::ofstream out(out_path, std::ios::binary);

    // Write Preamble
    out.write(preamble.c_str(), preamble.length());

    // Write Binary Delimiter
    out.write(BINARY_DELIMITER, 4);

    // Write Header
    out.write((char*)&header, sizeof(FileHeaderV3));

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

    return true;
}

bool Vault::decrypt_file(const fs::path& filepath) { // TODO: Test this method (modified by Gemini)
    std::ifstream in(filepath, std::ios::binary);
    if (!in) return false;

    // Search for BINARY_DELIMITER marker to skip preamble
    char delim[4];
    bool found_delim = false;
    while (in.read(delim, 4)) {
        if (memcmp(delim, BINARY_DELIMITER, 4) == 0) {
            found_delim = true;
            break;
        }
        // Move back 3 bytes to handle overlapping matches
        in.seekg(-3, std::ios::cur);
        
        // Safety: don't scan more than 8KB for the delimiter
        if (in.tellg() > 8192) break;
    }

    if (!found_delim) return false;

    char magic[4];
    if (!in.read(magic, 4) || memcmp(magic, MAGIC, 4) != 0) {
        return false;
    }

    unsigned char version;
    in.read((char*)&version, 1);
    
    unsigned char file_key[32];
    unsigned char iv[IV_LEN];

    if (version == VERSION_V3) {
        FileHeaderV3 header;
        memcpy(header.magic, magic, 4);
        header.version = version;
        in.read((char*)header.project_uuid, UUID_LEN);
        in.read((char*)header.file_id, FILE_ID_LEN);
        in.read((char*)header.milestone_id, FILE_ID_LEN);
        in.read((char*)&header.version_counter, 4);
        in.read((char*)&header.payload_size, 8);
        in.read((char*)header.salt, SALT_LEN);
        in.read((char*)header.iv, IV_LEN);
        memcpy(iv, header.iv, IV_LEN);

        // Verify project UUID
        unsigned char current_uuid_bytes[UUID_LEN];
        uuid_to_bytes(project_uuid, current_uuid_bytes);
        if (memcmp(header.project_uuid, current_uuid_bytes, UUID_LEN) != 0) {
            return false;
        }

        unsigned char milestone_key[32];
        if (header.milestone_id[0] != 0 || memcmp(header.milestone_id, header.milestone_id + 1, FILE_ID_LEN - 1) != 0) {
             // Milestone ID is not all zeros
             std::string m_id = bytes_to_uuid(header.milestone_id);
             bool released = false;
             for (const auto& m : milestones) {
                 if (m.id == m_id) {
                     released = m.is_released;
                     break;
                 }
             }
             if (!released) return false;
             derive_milestone_key(master_key.data(), header.milestone_id, milestone_key);
        } else {
             memcpy(milestone_key, master_key.data(), 32);
        }
        derive_file_key(milestone_key, header.file_id, file_key);

    } else if (version == VERSION_V2) {
        FileHeaderV2 header;
        memcpy(header.magic, magic, 4);
        header.version = version;
        in.read((char*)header.file_id, FILE_ID_LEN);
        in.read((char*)header.milestone_id, FILE_ID_LEN);
        in.read((char*)&header.version_counter, 4);
        in.read((char*)header.salt, SALT_LEN);
        in.read((char*)header.iv, IV_LEN);
        memcpy(iv, header.iv, IV_LEN);

        // Check if milestone is released
        std::string m_id = bytes_to_uuid(header.milestone_id);
        bool released = false;
        for (const auto& m : milestones) {
            if (m.id == m_id) {
                released = m.is_released;
                break;
            }
        }

        if (!released) {
            // Cannot decrypt if milestone is not released
            return false;
        }

        unsigned char milestone_key[32];
        derive_milestone_key(master_key.data(), header.milestone_id, milestone_key);
        derive_file_key(milestone_key, header.file_id, file_key);
    } else if (version == VERSION_V1) {
        FileHeaderV1 header;
        memcpy(header.magic, magic, 4);
        header.version = version;
        in.read((char*)header.file_id, FILE_ID_LEN);
        in.read((char*)header.salt, SALT_LEN);
        in.read((char*)header.iv, IV_LEN);
        memcpy(iv, header.iv, IV_LEN);

        derive_file_key(master_key.data(), header.file_id, file_key);
    } else {
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, file_key, iv);

    // Prepare output path in export/unlocked
    fs::path rel_locked_path = fs::relative(filepath, vault_root / export_root / "locked");
    std::string rel_unlocked_str = rel_locked_path.string();
    if (rel_unlocked_str.size() > 7 && rel_unlocked_str.substr(rel_unlocked_str.size() - 7) == ".locked") {
        rel_unlocked_str = rel_unlocked_str.substr(0, rel_unlocked_str.size() - 7);
    }
    fs::path out_path = vault_root / export_root / "unlocked" / rel_unlocked_str;
    fs::create_directories(out_path.parent_path());

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

    return true;
}

std::string Vault::share_file(const fs::path& filepath) { // TODO: Test this method (modified by Gemini)
    if (!fs::exists(filepath)) return "";
    
    std::ifstream in(filepath, std::ios::binary);
    if (!in) return "";

    // Search for BINARY_DELIMITER marker
    char delim[4];
    bool found_delim = false;
    while (in.read(delim, 4)) {
        if (memcmp(delim, BINARY_DELIMITER, 4) == 0) {
            found_delim = true;
            break;
        }
        in.seekg(-3, std::ios::cur);
        if (in.tellg() > 8192) break;
    }

    if (!found_delim) return "";

    char magic[4];
    if (!in.read(magic, 4) || memcmp(magic, MAGIC, 4) != 0) {
        return "";
    }

    unsigned char version;
    in.read((char*)&version, 1);

    unsigned char file_id[FILE_ID_LEN];

    if (version == VERSION_V3) {
        FileHeaderV3 header;
        in.seekg(-5, std::ios::cur); // Back to start of header
        in.read((char*)&header, sizeof(FileHeaderV3));
        memcpy(file_id, header.file_id, FILE_ID_LEN);
    } else if (version == VERSION_V2) {
        FileHeaderV2 header;
        in.seekg(-5, std::ios::cur);
        in.read((char*)&header, sizeof(FileHeaderV2));
        memcpy(file_id, header.file_id, FILE_ID_LEN);
    } else if (version == VERSION_V1) {
        FileHeaderV1 header;
        in.seekg(-5, std::ios::cur);
        in.read((char*)&header, sizeof(FileHeaderV1));
        memcpy(file_id, header.file_id, FILE_ID_LEN);
    } else {
        return "";
    }
    in.close();

    unsigned char file_key[32];
    derive_file_key(master_key.data(), file_id, file_key);

    // Convert keys/IDs to hex for JSON
    auto to_hex = [](const unsigned char* data, size_t len) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for(size_t i=0; i<len; ++i) ss << std::setw(2) << (int)data[i];
        return ss.str();
    };

    json token;
    token["fileID"] = to_hex(file_id, FILE_ID_LEN);
    token["key"] = to_hex(file_key, 32);
    token["fileName"] = filepath.filename().string();
    
    return token.dump(4);
}

bool Vault::decrypt_with_token(const std::string& token_json, const std::string& directory) { // TODO: Test this method (modified by Gemini)
    try {
        json token = json::parse(token_json);
        std::string target_id_hex = token.at("fileID").get<std::string>();
        std::string key_hex = token.at("key").get<std::string>();

        auto from_hex = [](const std::string& hex, unsigned char* out) {
            for (size_t i = 0; i < hex.length(); i += 2) {
                out[i / 2] = (unsigned char)std::stoi(hex.substr(i, 2), nullptr, 16);
            }
        };

        unsigned char file_key[32];
        from_hex(key_hex, file_key);

        // Scan directory for file with matching ID
        for (const auto& entry : fs::recursive_directory_iterator(directory)) {
            if (entry.is_regular_file() && entry.path().extension() == ".locked") {
                std::ifstream in(entry.path(), std::ios::binary);
                
                // Search for BINARY_DELIMITER
                char delim[4];
                bool found_delim = false;
                while (in.read(delim, 4)) {
                    if (memcmp(delim, BINARY_DELIMITER, 4) == 0) {
                        found_delim = true;
                        break;
                    }
                    in.seekg(-3, std::ios::cur);
                    if (in.tellg() > 8192) break;
                }
                if (!found_delim) continue;

                char magic[4];
                if (!in.read(magic, 4) || memcmp(magic, MAGIC, 4) != 0) {
                    continue;
                }

                unsigned char version;
                in.read((char*)&version, 1);
                
                unsigned char file_id[FILE_ID_LEN];
                unsigned char iv[IV_LEN];

                if (version == VERSION_V3) {
                    FileHeaderV3 h;
                    in.seekg(-5, std::ios::cur);
                    in.read((char*)&h, sizeof(FileHeaderV3));
                    memcpy(file_id, h.file_id, FILE_ID_LEN);
                    memcpy(iv, h.iv, IV_LEN);
                } else if (version == VERSION_V2) {
                    FileHeaderV2 h;
                    in.seekg(-5, std::ios::cur);
                    in.read((char*)&h, sizeof(FileHeaderV2));
                    memcpy(file_id, h.file_id, FILE_ID_LEN);
                    memcpy(iv, h.iv, IV_LEN);
                } else if (version == VERSION_V1) {
                    FileHeaderV1 h;
                    in.seekg(-5, std::ios::cur);
                    in.read((char*)&h, sizeof(FileHeaderV1));
                    memcpy(file_id, h.file_id, FILE_ID_LEN);
                    memcpy(iv, h.iv, IV_LEN);
                } else continue;

                std::stringstream ss;
                ss << std::hex << std::setfill('0');
                for(size_t i=0; i<FILE_ID_LEN; ++i) ss << std::setw(2) << (int)file_id[i];
                
                if (ss.str() == target_id_hex) {
                    // Found it! Decrypt.
                    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, file_key, iv);

                    std::string original_path = entry.path().string();
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


bool Vault::lock_vault(const std::string& milestone_id) { // TODO: Test this method (modified by Gemini)
    display_laser_grid();
    auto patterns = read_ignore_patterns();
    int count = 0;
    ConflictReport report;

    // Clear old conflict log
    fs::remove(vault_root / ".cipherlock" / "conflicts.log");

    for (const auto& entry : fs::recursive_directory_iterator(vault_root)) {
        if (entry.is_regular_file() && !should_ignore(entry.path(), patterns)) {
            if (encrypt_file(entry.path(), milestone_id)) {
                count++;
                std::cout << Theme::instance().color(Theme::SECONDARY) << I18n::instance().t("vault.locked", {{"path", fs::relative(entry.path(), vault_root).string()}}) << Theme::instance().color(Theme::RESET) << std::endl;
            } else {
                std::ifstream peek(entry.path(), std::ios::binary);
                if (peek) {
                    char buf[8192];
                    peek.read(buf, sizeof(buf));
                    std::string content(buf, peek.gcount());
                    if (content.find(project_uuid) != std::string::npos || content.find(MAGIC) != std::string::npos) {
                        report.conflicted_files.push_back(entry.path());
                    }
                }
            }
        }
    }
    is_armed = true;

    if (!report.conflicted_files.empty()) {
        report.save_to_file(vault_root / ".cipherlock" / "conflicts.log");
        report.print_summary();
    }

    save_config();

    // Update encryption count in config if needed (save_config might not do it)
    fs::path config_path = vault_root / ".cipherlock" / "config.json";
    std::ifstream ifs(config_path);
    json config;
    ifs >> config;
    ifs.close();
    config["encryption_date"] = std::chrono::system_clock::now().time_since_epoch().count();
    config["files_encrypted"] = count;
    std::ofstream ofs(config_path);
    ofs << config.dump(4);
    ofs.close();

    std::cout << "\n" << Theme::instance().color(Theme::SUCCESS) << I18n::instance().t("vault.armed_success", {{"count", std::to_string(count)}}) << Theme::instance().color(Theme::RESET) << std::endl;
    return true;
}

bool Vault::unlock_vault() { // TODO: Test this method (modified by Gemini)
    fs::path locked_dir = vault_root / export_root / "locked";
    if (!fs::exists(locked_dir)) {
        std::cout << "No locked files found in export directory.\n";
        return true;
    }

    int count = 0;
    std::vector<fs::path> orphaned_files;

    for (const auto& entry : fs::recursive_directory_iterator(locked_dir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".locked") {
            if (decrypt_file(entry.path())) {
                count++;
                
                // Check if source exists
                fs::path rel_locked = fs::relative(entry.path(), locked_dir);
                std::string rel_source_str = rel_locked.string();
                if (rel_source_str.size() > 7 && rel_source_str.substr(rel_source_str.size() - 7) == ".locked") {
                    rel_source_str = rel_source_str.substr(0, rel_source_str.size() - 7);
                }
                fs::path source_path = vault_root / rel_source_str;
                
                if (!fs::exists(source_path)) {
                    orphaned_files.push_back(source_path);
                }

                std::cout << Theme::instance().color(Theme::SUCCESS) << I18n::instance().t("vault.unlocked", {{"path", rel_source_str}}) << Theme::instance().color(Theme::RESET) << std::endl;
            }
        }
    }

    if (!orphaned_files.empty()) {
        std::cout << "\n" << Theme::instance().color(Theme::WARNING) << "⚠️  " << I18n::instance().t("signature.orphan_report_title") << Theme::instance().color(Theme::RESET) << "\n";
        for (const auto& orphan : orphaned_files) {
            std::cout << "  - " << fs::relative(orphan, vault_root).string() << "\n";
        }
    }

    is_armed = false;
    save_config();

    std::cout << "\n" << Theme::instance().color(Theme::SUCCESS) << I18n::instance().t("vault.disarmed_success", {{"count", std::to_string(count)}}) << Theme::instance().color(Theme::RESET) << std::endl;
    return true;
}

void Vault::display_status() const { // TODO: Test this method (modified by Gemini)
    std::string status = is_armed ? "ARMED 🔒" : "DISARMED 🔓";
    std::cout << "\n" << Theme::instance().color(Theme::SECONDARY) << I18n::instance().t("vault.status", {{"status", status}}) << Theme::instance().color(Theme::RESET) << std::endl;
    
    fs::path config_path = vault_root / ".cipherlock" / "config.json";
    if (fs::exists(config_path)) {
        try {
            std::ifstream config_file(config_path);
            json config;
            config_file >> config;
            
            std::string name = config.value("name", "Unknown Project");
            std::string uuid = config.value("uuid", "N/A");
            std::string description = config.value("description", "");
            std::string client = config.value("client", "");
            std::string deadline = config.value("deadline", "");
            double valuation = config.value("valuation", 0.0);
            long long setup_date_raw = config.value("setup_date", 0LL);
            std::string created_by = config.value("created_by", "Unknown");
            
            std::string key_location = "N/A";
            if (config.contains("master_key_info")) {
                key_location = config["master_key_info"].value("location", "N/A");
            }

            std::string display_currency = project_currency;
            std::transform(display_currency.begin(), display_currency.end(), display_currency.begin(), ::toupper);

            std::stringstream ss_val;
            ss_val << std::fixed << std::setprecision(2) << project_valuation;

            std::cout << I18n::instance().t("project.name_display", {{"name", project_name}}) << std::endl;
            std::cout << I18n::instance().t("project.uuid_display", {{"uuid", project_uuid}}) << std::endl;
            std::cout << "🔑 Master Key: " << key_location << std::endl;
            
            if (!project_client.empty()) {
                std::cout << I18n::instance().t("project.client_display", {{"client", project_client}}) << std::endl;
            }
            if (!project_deadline.empty()) {
                std::cout << I18n::instance().t("project.deadline_display", {{"deadline", project_deadline}}) << std::endl;
            }
            if (!project_description.empty()) {
                std::cout << I18n::instance().t("project.description_display", {{"description", project_description}}) << std::endl;
            }
            std::cout << I18n::instance().t("project.valuation_display", {{"value", ss_val.str()}, {"currency", display_currency}}) << std::endl;
            std::cout << I18n::instance().t("project.created_by", {{"profile", project_created_by}}) << std::endl;

            if (setup_date_raw > 0) {
                std::time_t setup_time = static_cast<std::time_t>(setup_date_raw);
                if (setup_date_raw > 2000000000LL) {
                     auto duration = std::chrono::system_clock::duration(setup_date_raw);
                     setup_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::time_point(duration));
                }
                
                std::cout << I18n::instance().t("project.setup_date_display", {{"date", std::ctime(&setup_time)}});
            }
        } catch (...) {
            std::cerr << "Error reading project metadata." << std::endl;
        }
    }

    std::cout << I18n::instance().t("vault.location", {{"path", vault_root.string()}}) << std::endl;
}

bool Vault::save_config() { // TODO: Test this method (Gemini)
    fs::path config_path = vault_root / ".cipherlock" / "config.json";
    json config;
    
    if (fs::exists(config_path)) {
        std::ifstream ifs(config_path);
        try {
            ifs >> config;
        } catch (...) {}
        ifs.close();
    }

    config["armed"] = is_armed;
    config["uuid"] = project_uuid;
    config["name"] = project_name;
    config["description"] = project_description;
    config["client"] = project_client;
    config["deadline"] = project_deadline;
    config["valuation"] = project_valuation;
    config["currency"] = project_currency;
    config["created_by"] = project_created_by;
    config["setup_date"] = project_setup_date;
    config["export_root"] = export_root.string();
    
    json milestones_json = json::array();
    for (const auto& m : milestones) {
        json m_json;
        m_json["id"] = m.id;
        m_json["name"] = m.name;
        m_json["description"] = m.description;
        m_json["is_released"] = m.is_released;
        m_json["valuation"] = m.valuation;
        m_json["currency"] = m.currency;
        m_json["created_at"] = m.created_at;
        m_json["released_at"] = m.released_at;
        milestones_json.push_back(m_json);
    }
    config["milestones"] = milestones_json;

    std::ofstream ofs(config_path);
    if (!ofs) return false;
    ofs << config.dump(4);
    return true;
}

bool Vault::create_milestone(const std::string& name, double valuation, const std::string& currency) { // TODO: Test this method (Gemini)
    Milestone m;
    m.id = generate_uuid();
    m.name = name;
    m.valuation = valuation;
    m.currency = currency;
    m.is_released = false;
    m.created_at = std::chrono::system_clock::now().time_since_epoch().count();
    m.released_at = 0;

    std::cout << I18n::instance().t("project.enter_milestone_description");
    std::string desc;
    std::getline(std::cin >> std::ws, desc);
    if (desc != "q" && desc != "Q") {
        m.description = desc;
    }

    milestones.push_back(m);
    if (save_config()) {
        std::cout << Theme::instance().color(Theme::SUCCESS) << I18n::instance().t("project.milestone_created", {{"name", name}}) << Theme::instance().color(Theme::RESET) << std::endl;
        return true;
    }
    return false;
}

void Vault::list_milestones() const { // TODO: Test this method (Gemini)
    if (milestones.empty()) {
        std::cout << "No milestones found." << std::endl;
        return;
    }

    std::cout << "\n" << Theme::instance().color(Theme::PRIMARY) << I18n::instance().t("project.milestone_list_title") << Theme::instance().color(Theme::RESET) << "\n";
    for (const auto& m : milestones) {
        std::string status = m.is_released ? I18n::instance().t("project.milestone_status_released") : I18n::instance().t("project.milestone_status_locked");
        std::string color = m.is_released ? Theme::SUCCESS : Theme::SECONDARY;
        
        std::string m_curr = m.currency;
        std::transform(m_curr.begin(), m_curr.end(), m_curr.begin(), ::toupper);

        std::stringstream ss_mval;
        ss_mval << std::fixed << std::setprecision(2) << m.valuation;

        std::cout << Theme::instance().color(color) 
                  << I18n::instance().t("project.milestone_item", {
                      {"id", m.id.substr(0, 8)}, 
                      {"name", m.name}, 
                      {"status", status}, 
                      {"valuation", ss_mval.str()}, 
                      {"currency", m_curr}
                  }) 
                  << Theme::instance().color(Theme::RESET) << std::endl;
    }
}

bool Vault::release_milestone(const std::string& milestone_id) { // TODO: Test this method (Gemini)
    for (auto& m : milestones) {
        if (m.id.substr(0, std::min(m.id.length(), milestone_id.length())) == milestone_id || m.id == milestone_id) {
            if (m.is_released) {
                std::cout << "Milestone already released." << std::endl;
                return true;
            }
            m.is_released = true;
            m.released_at = std::chrono::system_clock::now().time_since_epoch().count();
            if (save_config()) {
                std::cout << Theme::instance().color(Theme::SUCCESS) << I18n::instance().t("project.milestone_released", {{"name", m.name}}) << Theme::instance().color(Theme::RESET) << std::endl;
                return true;
            }
            return false;
        }
    }
    std::cout << Theme::instance().color(Theme::ERROR) << I18n::instance().t("project.milestone_not_found", {{"id", milestone_id}}) << Theme::instance().color(Theme::RESET) << std::endl;
    return false;
}

bool Vault::edit_milestone(const std::string& milestone_id) { // TODO: Test this method (Gemini)
    for (auto& m : milestones) {
        if (m.id.substr(0, std::min(m.id.length(), milestone_id.length())) == milestone_id || m.id == milestone_id) {
            std::cout << "\n" << Theme::instance().color(Theme::PRIMARY) << I18n::instance().t("project.milestone_edit_title", {{"name", m.name}}) << Theme::instance().color(Theme::RESET) << "\n";
            
            std::cout << "Enter new name [" << m.name << "] (q to skip): ";
            std::string name;
            std::getline(std::cin >> std::ws, name);
            if (!name.empty() && name != "q" && name != "Q") m.name = name;

            std::cout << "Enter new description [" << m.description << "] (q to skip): ";
            std::string desc;
            std::getline(std::cin, desc);
            if (!desc.empty()) {
                if (desc == "q" || desc == "Q") {} // skip
                else m.description = desc;
            }

            std::cout << "Enter new valuation [" << m.valuation << "] (q to skip): ";
            std::string val_str;
            std::getline(std::cin, val_str);
            if (!val_str.empty() && val_str != "q" && val_str != "Q") {
                try {
                    m.valuation = std::stod(val_str);
                } catch (...) {}
            }

            if (save_config()) {
                std::cout << Theme::instance().color(Theme::SUCCESS) << I18n::instance().t("project.milestone_updated") << Theme::instance().color(Theme::RESET) << std::endl;
                return true;
            }
            return false;
        }
    }
    std::cout << Theme::instance().color(Theme::ERROR) << I18n::instance().t("project.milestone_not_found", {{"id", milestone_id}}) << Theme::instance().color(Theme::RESET) << std::endl;
    return false;
}
