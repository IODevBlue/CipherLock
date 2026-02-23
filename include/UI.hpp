#ifndef UI_HPP
#define UI_HPP

#include <string>
#include <iostream>

namespace UI {
    const std::string LOGO = R"(
  ____ _       _               _                 _     
 / ___(_)_ __ | |__   ___ _ __| |    ___   ___| | __ 
| |   | | '_ \| '_ \ / _ \ '__| |   / _ \ / __| |/ / 
| |___| | |_) | | | |  __/ |  | |__| (_) | (__|   <  
 \____|_| .__/|_| |_|\___|_|  |_____\___/ \___|_|\_\ 
        |_|                                           
    )";
    // TODO: Check if this subtitle captures the functionality of this tooling
    const std::string SUBTITLE = "      >> SECURE CODEBASE ENCRYPTOR <<";

    inline void print_welcome(const std::string& version) {
        std::cout << "\033[1;36m" << LOGO << "\033[0m"; // Cyan logo
        std::cout << "\033[1;33m" << SUBTITLE << "\033[0m\n"; // Yellow subtitle
        std::cout << "             [ Version " << version << " ]\n" << std::endl;
    }

    inline void print_usage() {
        std::cout << "Usage:\n";
        std::cout << "  \033[1;32mcipherlock init [dir]\033[0m              Initialize a new vault (default: current dir)\n";
        std::cout << "  \033[1;32mcipherlock boot\033[0m                      Start interactive 'Hot' mode\n";
        std::cout << "  \033[1;32mcipherlock <src> <key_file> <dest>\033[0m   Run one-off 'Cold' encryption\n";
        std::cout << "  cipherlock --help | -h               Show this help message\n";
        std::cout << "  cipherlock --version | -v            Show version information\n";
    }
}

#endif // UI_HPP
