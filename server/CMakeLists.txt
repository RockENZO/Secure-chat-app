cmake_minimum_required(VERSION 3.10)

add_executable(server server.cpp)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(/opt/homebrew/include)  # Include websocketpp and jsoncpp
target_link_libraries(server ${OPENSSL_LIBRARIES} Threads::Threads)
target_link_libraries(server OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
target_link_libraries(server /opt/homebrew/lib/libjsoncpp.dylib)  # Link jsoncpp