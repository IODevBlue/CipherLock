#ifndef SIGNATURE_ENGINE_HPP
#define SIGNATURE_ENGINE_HPP

#include <string>
#include <vector>
#include <filesystem>
#include <map>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>

namespace fs = std::filesystem;

namespace cipherLock {

/**
 * @brief Configuration for file signatures.
 */
struct SignatureConfig { // TODO: Test this method (Gemini)
    struct HeaderConfig {
        std::string template_path = ".cipherlock/signature_header.txt";
        std::string comment_style = "auto";
        bool enforce_visibility = true;
    } header;

    /**
     * @brief Loads signature configuration from a file.
     * @param path The path to the configuration file (YAML).
     * @return The loaded SignatureConfig.
     */
    static SignatureConfig load(const fs::path& path) { // TODO: Test this method (Gemini)
        SignatureConfig config;
        std::ifstream ifs(path);
        if (!ifs.is_open()) return config;

        std::string line;
        while (std::getline(ifs, line)) {
            // Very basic YAML-like parsing for the required fields
            if (line.find("template_path:") != std::string::npos) {
                size_t start = line.find("\"") + 1;
                size_t end = line.find_last_of("\"");
                if (start != std::string::npos && end != std::string::npos && end > start) {
                    config.header.template_path = line.substr(start, end - start);
                }
            } else if (line.find("comment_style:") != std::string::npos) {
                size_t start = line.find("\"") + 1;
                size_t end = line.find_last_of("\"");
                if (start != std::string::npos && end != std::string::npos && end > start) {
                    config.header.comment_style = line.substr(start, end - start);
                }
            } else if (line.find("enforce_visibility:") != std::string::npos) {
                config.header.enforce_visibility = (line.find("true") != std::string::npos);
            }
        }
        return config;
    }
};

/**
 * @brief Handles generation of human-readable preambles for encrypted files.
 */
class SignatureEngine { // TODO: Test this method (Gemini)
public:
    enum class CommentStyle {
        BLOCK_C,    // /* ... */
        HASH,       // # ...
        DASH,       // -- ...
        XML,        // <!-- ... -->
        NONE        // No wrapping
    };

    /**
     * @brief Resolves placeholders in a template string.
     * @param template_str The template string containing {{PLACEHOLDERS}}.
     * @param variables A map of placeholder names to their values.
     * @return The resolved string.
     */
    static std::string resolve_placeholders(const std::string& template_str, const std::map<std::string, std::string>& variables) { // TODO: Test this method (Gemini)
        std::string resolved = template_str;
        for (const auto& [key, value] : variables) {
            std::string placeholder = "{{" + key + "}}";
            size_t pos = 0;
            while ((pos = resolved.find(placeholder, pos)) != std::string::npos) {
                resolved.replace(pos, placeholder.length(), value);
                pos += value.length();
            }
        }
        return resolved;
    }

    /**
     * @brief Detects the appropriate comment style for a given file extension.
     * @param extension The file extension (including the dot).
     * @return The detected CommentStyle.
     */
    static CommentStyle detect_style(const std::string& extension) { // TODO: Test this method (Gemini)
        static const std::map<std::string, CommentStyle> style_map = {
            {".cpp", CommentStyle::BLOCK_C}, {".hpp", CommentStyle::BLOCK_C},
            {".c", CommentStyle::BLOCK_C}, {".h", CommentStyle::BLOCK_C},
            {".cc", CommentStyle::BLOCK_C}, {".hh", CommentStyle::BLOCK_C},
            {".js", CommentStyle::BLOCK_C}, {".ts", CommentStyle::BLOCK_C},
            {".jsx", CommentStyle::BLOCK_C}, {".tsx", CommentStyle::BLOCK_C},
            {".css", CommentStyle::BLOCK_C}, {".scss", CommentStyle::BLOCK_C},
            {".sass", CommentStyle::BLOCK_C}, {".less", CommentStyle::BLOCK_C},
            {".java", CommentStyle::BLOCK_C}, {".kt", CommentStyle::BLOCK_C},
            {".go", CommentStyle::BLOCK_C}, {".rs", CommentStyle::BLOCK_C},
            {".swift", CommentStyle::BLOCK_C}, {".m", CommentStyle::BLOCK_C},
            {".mm", CommentStyle::BLOCK_C}, {".cs", CommentStyle::BLOCK_C},
            {".py", CommentStyle::HASH}, {".sh", CommentStyle::HASH},
            {".bash", CommentStyle::HASH}, {".zsh", CommentStyle::HASH},
            {".yaml", CommentStyle::HASH}, {".yml", CommentStyle::HASH},
            {".rb", CommentStyle::HASH}, {".pl", CommentStyle::HASH},
            {".php", CommentStyle::HASH}, {".pyw", CommentStyle::HASH},
            {".lua", CommentStyle::DASH}, {".sql", CommentStyle::DASH},
            {".hs", CommentStyle::DASH}, {".ada", CommentStyle::DASH},
            {".html", CommentStyle::XML}, {".xml", CommentStyle::XML},
            {".svg", CommentStyle::XML}, {".xaml", CommentStyle::XML},
            {".vue", CommentStyle::XML}
        };

        auto it = style_map.find(extension);
        if (it != style_map.end()) {
            return it->second;
        }
        return CommentStyle::NONE;
    }

    /**
     * @brief Wraps a text block in the appropriate comment syntax.
     * @param text The text to wrap.
     * @param style The CommentStyle to use.
     * @return The wrapped text.
     */
    static std::string wrap_text(const std::string& text, CommentStyle style) { // TODO: Test this method (Gemini)
        if (style == CommentStyle::NONE) return text;

        std::stringstream ss(text);
        std::string line;
        std::string wrapped;

        switch (style) {
            case CommentStyle::BLOCK_C:
                wrapped = "/*\n";
                while (std::getline(ss, line)) {
                    wrapped += " * " + line + "\n";
                }
                wrapped += " */\n";
                break;
            case CommentStyle::HASH:
                while (std::getline(ss, line)) {
                    wrapped += "# " + line + "\n";
                }
                break;
            case CommentStyle::DASH:
                while (std::getline(ss, line)) {
                    wrapped += "-- " + line + "\n";
                }
                break;
            case CommentStyle::XML:
                wrapped = "<!--\n";
                while (std::getline(ss, line)) {
                    wrapped += "  " + line + "\n";
                }
                wrapped += "-->\n";
                break;
            default:
                wrapped = text;
        }
        return wrapped;
    }

    /**
     * @brief Generates a full preamble for a file.
     * @param filepath The path to the file (used for extension detection).
     * @param template_path The path to the signature template file.
     * @param variables Map of placeholders to values.
     * @return The final preamble string.
     */
    static std::string generate_preamble(const fs::path& filepath, const fs::path& template_path, const std::map<std::string, std::string>& variables) { // TODO: Test this method (Gemini)
        std::ifstream t_file(template_path);
        if (!t_file.is_open()) return "";

        std::stringstream buffer;
        buffer << t_file.rdbuf();
        std::string template_content = buffer.str();

        std::string resolved = resolve_placeholders(template_content, variables);
        CommentStyle style = detect_style(filepath.extension().string());
        
        return wrap_text(resolved, style);
    }
};

} // namespace cipherLock

#endif // SIGNATURE_ENGINE_HPP
