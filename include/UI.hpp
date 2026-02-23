#ifndef UI_HPP
#define UI_HPP

#include <string>
#include <iostream>
#include "I18n.hpp" // Include I18n for localization

namespace UI {
    const std::string LOGO = R"(
  ____ _       _               _                 _     
 / ___(_)_ __ | |__   ___ _ __| |    ___   ___| | __ 
| |   | | '_ \| '_ \ / _ \ '__| |   / _ \ / __| |/ / 
| |___| | |_) | | | |  __/ |  | |__| (_) | (__|   <  
 \____|_| .__/|_| |_|\___|_|  |_____\___/ \___|_|\_\ 
        |_|                                           
    )";

    inline void print_welcome(const std::string& version, const std::string& lang) { // TODO: Test this method (modified by Gemini)
        std::cout << "\033[1;36m" << LOGO << "\033[0m"; // Cyan logo
        std::cout << "\033[1;33m" << I18n::instance().t("ui.subtitle") << "\033[0m\n"; // Yellow subtitle
        std::cout << I18n::instance().t("ui.welcome", {{"version", version}, {"lang", lang}}) << "\n" << std::endl;
    }

    inline void print_usage() { // TODO: Test this method (modified by Gemini)
        std::cout << I18n::instance().t("ui.usage_title") << "\n";
        std::cout << "  \033[1;32mcipherlock init [dir]\033[0m              " << I18n::instance().t("ui.usage_init") << "\n";
        std::cout << "  \033[1;32mcipherlock boot\033[0m                      " << I18n::instance().t("ui.usage_boot") << "\n";
        std::cout << "  \033[1;32mcipherlock lang [code|--list]\033[0m       " << I18n::instance().t("ui.usage_lang") << "\n";
        std::cout << "  \033[1;32mcipherlock <src> <key_file> <dest>\033[0m   " << I18n::instance().t("ui.usage_cold") << "\n";
        std::cout << "  cipherlock --help | -h               " << I18n::instance().t("ui.usage_help") << "\n";
        std::cout << "  cipherlock --version | -v            " << I18n::instance().t("ui.usage_version") << "\n";
    }
}

#endif // UI_HPP
