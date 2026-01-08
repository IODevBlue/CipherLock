``` C++
#include <iostream>
#include <chrono>
#include <iomanip>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <vector>
#include <algorithm>
#include <cmath>

class TOTP_VaultBreaker {
private:
    std::vector<unsigned char> secret_key;
    int digits = 6;
    int time_step = 30; // seconds
    
    // 🔥 "Mission: Impossible" style countdown display
    void display_countdown(int seconds_left) {
        std::cout << "\n🕒 Access window closes in: " << seconds_left << " seconds ";
        std::cout << "[";
        int bars = 20 - (seconds_left * 20 / time_step);
        for(int i = 0; i < 20; i++) {
            if(i < bars) std::cout << "█";
            else std::cout << "░";
        }
        std::cout << "]\r" << std::flush;
    }
    
    // 🎯 Generate HMAC-SHA1
    std::vector<unsigned char> hmac_sha1(const std::vector<unsigned char>& key, 
                                        const std::vector<unsigned char>& msg) {
        std::vector<unsigned char> result(EVP_MAX_MD_SIZE);
        unsigned int len = 0;
        
        HMAC(EVP_sha1(), key.data(), key.size(), 
             msg.data(), msg.size(), result.data(), &len);
        result.resize(len);
        return result;
    }
    
    // 🎲 Dynamic truncation (RFC 4226)
    int dynamic_truncation(const std::vector<unsigned char>& hash) {
        int offset = hash[hash.size() - 1] & 0xF;
        int binary = ((hash[offset] & 0x7F) << 24) |
                    ((hash[offset + 1] & 0xFF) << 16) |
                    ((hash[offset + 2] & 0xFF) << 8) |
                    (hash[offset + 3] & 0xFF);
        return binary;
    }

public:
    // 🕵️‍♂️ Initialize with secret (or generate random)
    TOTP_VaultBreaker(const std::string& secret = "") {
        if(secret.empty()) {
            // Generate random 20-byte secret like a spy would
            secret_key.resize(20);
            std::generate(secret_key.begin(), secret_key.end(), []() {
                return rand() % 256;
            });
            std::cout << "🔐 Generated random secret key (keep this safe!)\n";
        } else {
            secret_key.assign(secret.begin(), secret.end());
        }
    }
    
    // ⏱️ Get current TOTP
    std::string get_current_totp() {
        // Get current Unix time / time_step
        auto now = std::chrono::system_clock::now();
        auto epoch = now.time_since_epoch();
        auto time_step_count = std::chrono::duration_cast<std::chrono::seconds>(epoch).count() / time_step;
        
        // Convert time_step_count to 8-byte big-endian
        std::vector<unsigned char> time_bytes(8);
        for(int i = 7; i >= 0; i--) {
            time_bytes[i] = time_step_count & 0xFF;
            time_step_count >>= 8;
        }
        
        // Generate HMAC
        auto hmac_result = hmac_sha1(secret_key, time_bytes);
        
        // Generate TOTP
        int code = dynamic_truncation(hmac_result) % (int)pow(10, digits);
        
        // Format with leading zeros
        std::stringstream ss;
        ss << std::setw(digits) << std::setfill('0') << code;
        return ss.str();
    }
    
    // 🎬 Main authentication sequence (Bond/Splinter Cell style)
    bool authenticate_sequence() {
        std::cout << "\n╔══════════════════════════════════════════╗\n";
        std::cout << "║   SECURE VAULT ACCESS - TOTP REQUIRED    ║\n";
        std::cout << "╚══════════════════════════════════════════╝\n";
        
        auto start_time = std::chrono::system_clock::now();
        int attempts = 3;
        
        while(attempts > 0) {
            // Calculate time remaining in current window
            auto now = std::chrono::system_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - start_time).count();
            int time_remaining = time_step - (elapsed % time_step);
            
            display_countdown(time_remaining);
            
            std::cout << "\n\n🔢 Enter " << digits << "-digit code (Attempts left: " << attempts << "): ";
            std::string user_input;
            std::cin >> user_input;
            
            std::string current_totp = get_current_totp();
            
            if(user_input == current_totp) {
                std::cout << "\n✅ ACCESS GRANTED!\n";
                std::cout << "   Vault doors opening...\n";
                std::cout << "   Mission accomplished, agent. 🍸\n";
                return true;
            } else {
                attempts--;
                std::cout << "\n❌ ACCESS DENIED!\n";
                
                if(attempts > 0) {
                    std::cout << "⚠️  Warning: " << attempts << " attempt(s) remaining\n";
                    if(attempts == 1) {
                        std::cout << "🚨 Final attempt - security systems arming...\n";
                    }
                } else {
                    std::cout << "\n🚨🚨🚨 INTRUDER ALERT! 🚨🚨🚨\n";
                    std::cout << "   Laser defenses: ACTIVATED\n";
                    std::cout << "   Security teams: DISPATCHED\n";
                    std::cout << "   Self-destruct: ARMED\n";
                    std::cout << "💥 Get to the extraction point! 💥\n";
                }
            }
        }
        return false;
    }
    
    // 📟 Display current code (for debugging/spy prep)
    void display_current_status() {
        auto now = std::chrono::system_clock::now();
        auto epoch = now.time_since_epoch();
        int current_seconds = std::chrono::duration_cast<std::chrono::seconds>(epoch).count() % time_step;
        
        std::cout << "\n📡 TOTP Status:\n";
        std::cout << "   Current code: " << get_current_totp() << "\n";
        std::cout << "   Time left: " << (time_step - current_seconds) << "s\n";
        std::cout << "   Step size: " << time_step << "s\n";
    }
};

// 🎥 Main mission
int main() {
    srand(time(nullptr));
    
    std::cout << "=== S.P.Y. TOTP GENERATOR v1.0 ===\n";
    std::cout << "For authorized agents only\n\n";
    
    // You could use a pre-shared secret or generate random
    TOTP_VaultBreaker vault("Sup3rS3cr3tK3y!"); // Default secret
    
    // Display current status
    vault.display_current_status();
    
    // Start authentication sequence
    bool success = vault.authenticate_sequence();
    
    if(success) {
        std::cout << "\n🎉 Mission successful. The world is safe... for now.\n";
    } else {
        std::cout << "\n💀 Mission failed. Better luck next time, agent.\n";
    }
    
    return success ? 0 : 1;
}
```

To compile and run:
```bash
# Install OpenSSL development libraries if needed
# sudo apt-get install libssl-dev  # Ubuntu/Debian
# brew install openssl              # macOS

g++ -std=c++11 -o totp_vault totp_vault.cpp -lssl -lcrypto
./totp_vault

```

---

TODO
----
[ ] Add QR code generation for secret sharing
[ ] Implement backup codes (in case Q gets captured)
[ ] Add network time synchronization (NTP)
[ ] GUI version with blinking red LEDs
[ ] Self-destruct feature that deletes the binary after 3 failed attempts 😆




