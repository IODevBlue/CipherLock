cmake_minimum_required(VERSION 3.14)
project(CipherLock VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(include)

# Executable
file(GLOB_RECURSE SOURCES src/*.cpp)
add_executable(cipherlock ${SOURCES})

# Link libraries
target_link_libraries(cipherlock 
    PRIVATE 
    OpenSSL::SSL 
    OpenSSL::Crypto
)
