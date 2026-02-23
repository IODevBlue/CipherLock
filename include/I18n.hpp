#ifndef I18N_HPP
#define I18N_HPP

#include <string>
#include <map>
#include <vector>
#include <fstream>
#include <iostream>
#include <sstream>
#include <filesystem>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

class I18n { // TODO: Test this method (Gemini)
public:
    static I18n& instance() {
        static I18n instance;
        return instance;
    }

    void load(const std::string& locale, const std::string& locale_dir = "locales") {
        std::string path = locale_dir + "/" + locale + ".json";
        std::ifstream file(path);
        if (!file.is_open()) {
            std::cerr << "DEBUG: Failed to open locale file at " << path << std::endl;
            // Fallback or handle error
            if (locale != "en") {
                load("en", locale_dir);
            }
            return;
        }

        try {
            file >> translations;
            current_locale = locale;
        } catch (const std::exception& e) {
            std::cerr << "Error loading locale " << locale << ": " << e.what() << std::endl;
        }
    }

    std::string t(const std::string& key, const std::map<std::string, std::string>& vars = {}) {
        try {
            // Support nested keys like "vault.initialized"
            json current = translations;
            std::string segment;
            std::stringstream ss(key);
            while (std::getline(ss, segment, '.')) {
                if (current.contains(segment)) {
                    current = current[segment];
                } else {
                    return key; // Return key as fallback
                }
            }

            if (!current.is_string()) return key;

            std::string val = current.get<std::string>();
            for (const auto& [name, replacement] : vars) {
                std::string placeholder = "{" + name + "}";
                size_t pos = 0;
                while ((pos = val.find(placeholder, pos)) != std::string::npos) {
                    val.replace(pos, placeholder.length(), replacement);
                    pos += replacement.length();
                }
            }
            return val;
        } catch (...) {
            return key;
        }
    }

    std::string getLanguageName() const {
        if (translations.contains("_meta") && translations["_meta"].contains("name")) {
            return translations["_meta"]["name"];
        }
        return current_locale;
    }

    std::vector<std::string> getAvailableLanguages(const std::string& locale_dir = "locales") {
        std::vector<std::string> languages;
        for (const auto& entry : fs::directory_iterator(locale_dir)) {
            if (entry.path().extension() == ".json") {
                std::ifstream file(entry.path());
                if (file.is_open()) {
                    try {
                        json lang_json;
                        file >> lang_json;
                        if (lang_json.contains("_meta") && lang_json["_meta"].contains("name")) {
                            languages.push_back(lang_json["_meta"]["name"]);
                        }
                    } catch (...) {
                        // Ignore files that fail to parse
                    }
                }
            }
        }
        return languages;
    }
    
    std::string getCurrentLocale() const {
        return current_locale;
    }

private:
    I18n() {
        load("en", "../locales");
    };
    json translations;
    std::string current_locale;
};

#endif
