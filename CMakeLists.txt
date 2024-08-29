cmake_minimum_required(VERSION 3.10)
project(DistributedChat)

set(CMAKE_CXX_STANDARD 17)

# Include directories
include_directories(${PROJECT_SOURCE_DIR}/dependencies)

# Add source files
set(SOURCES
    src/main.cpp
    src/server.cpp
    src/client.cpp
    src/message.cpp
    src/encryption.cpp
)

# Find and include dependencies
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)

# Link libraries
add_executable(DistributedChat ${SOURCES})
target_link_libraries(DistributedChat OpenSSL::SSL OpenSSL::Crypto nlohmann_json::nlohmann_json)