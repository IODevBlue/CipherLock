#include "TOTP.hpp"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cmath>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <iostream>

TOTP::TOTP(const std::string& secret, bool is_base32) { // TODO: Test this method (Gemini)
    if (secret.empty()) {
        secret_key.resize(20);
        RAND_bytes(secret_key.data(), 20);
    } else if (is_base32) {
        // Simple Base32 decoding
        int buffer = 0, bits_left = 0;
        for (char c : secret) {
            int val = -1;
            if (c >= 'A' && c <= 'Z') val = c - 'A';
            else if (c >= 'a' && c <= 'z') val = c - 'a';
            else if (c >= '2' && c <= '7') val = c - '2' + 26;
            
            if (val >= 0) {
                buffer = (buffer << 5) | val;
                bits_left += 5;
                if (bits_left >= 8) {
                    bits_left -= 8;
                    secret_key.push_back((unsigned char)((buffer >> bits_left) & 0xFF));
                }
            }
        }
    } else {
        secret_key.assign(secret.begin(), secret.end());
    }
}

TOTP::~TOTP() { // TODO: Test this method (Gemini)
    zeroize_secret();
}

void TOTP::zeroize_secret() { // TODO: Test this method (Gemini)
    // TODO: Consider using OPENSSL_cleanse(secret_key.data(), secret_key.size()) for guaranteed memory wiping.
    std::fill(secret_key.begin(), secret_key.end(), 0);
}

std::string TOTP::generate(uint64_t timestamp) { // TODO: Test this method (Gemini)
    uint64_t T = timestamp / time_step;
    
    unsigned char timeBytes[8];
    for (int i = 7; i >= 0; i--) {
        timeBytes[i] = T & 0xFF;
        T >>= 8;
    }

    unsigned char hmacResult[EVP_MAX_MD_SIZE];
    unsigned int hmacLength;

    HMAC(EVP_sha1(), secret_key.data(), secret_key.size(),
         timeBytes, 8, hmacResult, &hmacLength);

    int offset = hmacResult[hmacLength - 1] & 0x0F;
    uint32_t binary = ((hmacResult[offset] & 0x7F) << 24) |
                     ((hmacResult[offset + 1] & 0xFF) << 16) |
                     ((hmacResult[offset + 2] & 0xFF) << 8) |
                     (hmacResult[offset + 3] & 0xFF);

    uint32_t otp = binary % static_cast<uint32_t>(pow(10, digits));
    
    std::stringstream ss;
    ss << std::setw(digits) << std::setfill('0') << otp;
    return ss.str();
}

std::string TOTP::generate_current() { // TODO: Test this method (Gemini)
    auto now = std::chrono::system_clock::now();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    return generate(seconds);
}

bool TOTP::verify(const std::string& code) { // TODO: Test this method (Gemini)
    auto now = std::chrono::system_clock::now();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();

    // Check current, previous, and next window to allow for clock skew
    for (int i = -1; i <= 1; ++i) {
        if (generate(seconds + (i * time_step)) == code) {
            return true;
        }
    }
    return false;
}

std::string TOTP::get_base32_secret() const { // TODO: Test this method (Gemini)
    const char* base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string result;
    int buffer = 0;
    int bits_left = 0;

    for (unsigned char byte : secret_key) {
        buffer = (buffer << 8) | byte;
        bits_left += 8;
        while (bits_left >= 5) {
            bits_left -= 5;
            result += base32_chars[(buffer >> bits_left) & 0x1F];
        }
    }
    if (bits_left > 0) {
        result += base32_chars[(buffer << (5 - bits_left)) & 0x1F];
    }
    return result;
}

int TOTP::get_seconds_remaining() const { // TODO: Test this method (Gemini)
    auto now = std::chrono::system_clock::now();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    return time_step - (seconds % time_step);
}
