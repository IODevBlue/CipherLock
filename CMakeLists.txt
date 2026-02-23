cmake_minimum_required(VERSION 3.14)
project(CipherLock VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(include)

# Executable
add_executable(cipherlock 
    src/main.cpp 
    src/Vault.cpp 
    src/TOTP.cpp
)

# Link libraries
target_link_libraries(cipherlock 
    PRIVATE 
    OpenSSL::SSL 
    OpenSSL::Crypto
)
