#include "Theme.hpp"
#include <fstream>
#include <iostream>
#include <algorithm>

using json = nlohmann::json;

Theme::Theme() {
    loadDefault();
}

void Theme::loadDefault() {
    currentThemeName = "default";
    colorMap["primary"]   = "\033[1;36m";
    colorMap["secondary"] = "\033[1;33m";
    colorMap["success"]   = "\033[1;32m";
    colorMap["error"]     = "\033[1;31m";
    colorMap["warning"]   = "\033[1;33m";
    colorMap["info"]      = "\033[1;34m";
    colorMap["accent"]    = "\033[1;35m";
    colorMap["prompt"]    = "\033[1;32m";
}

bool Theme::load(const std::string& themeName, const std::string& themesDir) {
    // Determine user home directory for persistent themes
    std::string home;
#ifdef _WIN32
    const char* userProfile = getenv("USERPROFILE");
    if (userProfile) home = userProfile;
#else
    const char* homeEnv = getenv("HOME");
    if (homeEnv) home = homeEnv;
#endif

    std::vector<fs::path> searchPaths = {
        fs::path(themesDir) / (themeName + ".json")
    };
    
    if (!home.empty()) {
        searchPaths.push_back(fs::path(home) / ".cipherlock" / "themes" / (themeName + ".json"));
    }

    for (const auto& themePath : searchPaths) {
        if (fs::exists(themePath)) {
            try {
                std::ifstream file(themePath);
                json themeData = json::parse(file);
                
                json colors = themeData.at("colors");
                colorMap["primary"]   = colors.at("primary").get<std::string>();
                colorMap["secondary"] = colors.at("secondary").get<std::string>();
                colorMap["success"]   = colors.at("success").get<std::string>();
                colorMap["error"]     = colors.at("error").get<std::string>();
                colorMap["warning"]   = colors.value("warning", "\033[1;33m");
                colorMap["info"]      = colors.at("info").get<std::string>();
                colorMap["accent"]    = colors.at("accent").get<std::string>();
                colorMap["prompt"]    = colors.at("prompt").get<std::string>();
                
                currentThemeName = themeName;
                return true;
            } catch (...) {
                continue;
            }
        }
    }
    
    return false;
}

std::string Theme::color(const std::string& style) const {
    auto it = colorMap.find(style);
    if (it != colorMap.end()) return it->second;
    return RESET_CODE;
}

std::string Theme::apply(const std::string& text, const std::string& style) const {
    return color(style) + text + RESET_CODE;
}

std::vector<std::string> Theme::getAvailableThemes(const std::string& themesDir) const {
    std::vector<std::string> themes;
    
    std::string home;
#ifdef _WIN32
    const char* userProfile = getenv("USERPROFILE");
    if (userProfile) home = userProfile;
#else
    const char* homeEnv = getenv("HOME");
    if (homeEnv) home = homeEnv;
#endif

    std::vector<fs::path> searchDirs = {
        fs::path(themesDir)
    };
    
    if (!home.empty()) {
        searchDirs.push_back(fs::path(home) / ".cipherlock" / "themes");
    }

    for (const auto& dir : searchDirs) {
        if (fs::exists(dir) && fs::is_directory(dir)) {
            for (const auto& entry : fs::directory_iterator(dir)) {
                if (entry.path().extension() == ".json") {
                    std::string name = entry.path().stem().string();
                    if (std::find(themes.begin(), themes.end(), name) == themes.end()) {
                        themes.push_back(name);
                    }
                }
            }
        }
    }
    return themes;
}
