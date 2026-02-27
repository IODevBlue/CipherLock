#ifndef THEME_HPP
#define THEME_HPP

#include <string>
#include <map>
#include <vector>
#include <filesystem>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;

/**
 * @brief Manages CipherLock UI themes via JSON configuration.
 */
class Theme {
public:
    static Theme& instance() {
        static Theme inst;
        return inst;
    }

    /**
     * @brief Loads a theme from a JSON file.
     * @param themeName The name of the theme (e.g., "matrix").
     * @param themesDir The directory containing theme JSONs.
     * @return true if loaded successfully.
     */
    bool load(const std::string& themeName, const std::string& themesDir = "../themes");

    /**
     * @brief Returns the ANSI escape code for a logical style.
     */
    std::string color(const std::string& style) const;

    /**
     * @brief Wraps text in the ANSI code for a style and resets it.
     */
    std::string apply(const std::string& text, const std::string& style) const;

    std::string getCurrentThemeName() const { return currentThemeName; }
    std::vector<std::string> getAvailableThemes(const std::string& themesDir = "../themes") const;

    // Logical Style Keys
    static constexpr const char* PRIMARY   = "primary";
    static constexpr const char* SECONDARY = "secondary";
    static constexpr const char* SUCCESS   = "success";
    static constexpr const char* ERROR     = "error";
    static constexpr const char* INFO      = "info";
    static constexpr const char* ACCENT    = "accent";
    static constexpr const char* PROMPT    = "prompt";
    static constexpr const char* RESET     = "reset";

private:
    Theme();
    std::string currentThemeName;
    std::map<std::string, std::string> colorMap;
    const std::string RESET_CODE = "\033[0m";

    void loadDefault();
};

#endif // THEME_HPP
