#ifndef UI_HPP
#define UI_HPP

#include <string>
#include <iostream>
#include "I18n.hpp" // Include I18n for localization
#include "Theme.hpp"

namespace UI {
    const std::string LOGO = R"(
  ____ _       _               _                 _     
 / ___(_)_ __ | |__   ___ _ __| |    ___   ___| | __ 
| |   | | '_ \| '_ \ / _ \ '__| |   / _ \ / __| |/ / 
| |___| | |_) | | | |  __/ |  | |__| (_) | (__|   <  
 \____|_| .__/|_| |_|\___|_|  |_____\___/ \___|_|\_\ 
        |_|                                           
    )";

    inline void print_welcome(const std::string& version, const std::string& lang, const std::string& activeProfileName = "") { // TODO: Test this method (modified by Gemini)
        std::cout << Theme::instance().color(Theme::PRIMARY) << LOGO << Theme::instance().color(Theme::RESET); 
        std::cout << Theme::instance().color(Theme::SECONDARY) << I18n::instance().t("ui.subtitle") << Theme::instance().color(Theme::RESET) << "\n";
        std::cout << I18n::instance().t("ui.welcome", {{"version", version}, {"lang", lang}}) << "\n";
        if (!activeProfileName.empty()) {
            std::cout << I18n::instance().t("ui.active_profile_display", {{"profile_name", activeProfileName}}) << "\n";
        }
        std::cout << std::endl;
    }

    inline void print_usage() { // TODO: Test this method (modified by Gemini)
        std::cout << std::endl;
        std::cout << I18n::instance().t("ui.usage_title") << "\n";
        std::cout << "  " << Theme::instance().color(Theme::SUCCESS) << "cipherlock boot [dir]" << Theme::instance().color(Theme::RESET) << "              " << I18n::instance().t("ui.usage_boot") << "\n";
        std::cout << "  " << Theme::instance().color(Theme::SUCCESS) << "cipherlock edit --project [dir]" << Theme::instance().color(Theme::RESET) << "     " << I18n::instance().t("ui.usage_edit") << "\n";
        std::cout << "  " << Theme::instance().color(Theme::SUCCESS) << "cipherlock lang [code | --list]" << Theme::instance().color(Theme::RESET) << "       " << I18n::instance().t("ui.usage_lang") << "\n";
        std::cout << "  " << Theme::instance().color(Theme::SUCCESS) << "cipherlock profile <subcommand> [args]" << Theme::instance().color(Theme::RESET) << " " << I18n::instance().t("ui.usage_profile") << "\n";
        std::cout << "    " << Theme::instance().color(Theme::INFO) << "create [name]" << Theme::instance().color(Theme::RESET) << "                  " << I18n::instance().t("ui.usage_profile_create") << "\n";
        std::cout << "    " << Theme::instance().color(Theme::INFO) << "list" << Theme::instance().color(Theme::RESET) << "                           " << I18n::instance().t("ui.usage_profile_list") << "\n";
        std::cout << "    " << Theme::instance().color(Theme::INFO) << "set-active [name]" << Theme::instance().color(Theme::RESET) << "              " << I18n::instance().t("ui.usage_profile_set_active") << "\n";
        std::cout << "    " << Theme::instance().color(Theme::INFO) << "get-active" << Theme::instance().color(Theme::RESET) << "                     " << I18n::instance().t("ui.usage_profile_get_active") << "\n";
        std::cout << "  " << Theme::instance().color(Theme::SUCCESS) << "cipherlock share <file> [dir]" << Theme::instance().color(Theme::RESET) << "      " << I18n::instance().t("ui.usage_share") << "\n";
        std::cout << "  " << Theme::instance().color(Theme::SUCCESS) << "cipherlock unlock-file <token> [dir]" << Theme::instance().color(Theme::RESET) << " " << I18n::instance().t("ui.usage_unlock_file") << "\n";
        std::cout << "  " << Theme::instance().color(Theme::SUCCESS) << "cipherlock --help | -h" << Theme::instance().color(Theme::RESET) << "               " << I18n::instance().t("ui.usage_help") << "\n";
        std::cout << "  " << Theme::instance().color(Theme::SUCCESS) << "cipherlock --version | -v" << Theme::instance().color(Theme::RESET) << "            " << I18n::instance().t("ui.usage_version") << "\n";
    }
}

#endif // UI_HPP
