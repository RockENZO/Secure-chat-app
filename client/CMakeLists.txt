cmake_minimum_required(VERSION 3.10)

add_executable(client client.cpp)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(/opt/homebrew/include)  # Include websocketpp and jsoncpp
target_link_libraries(client ${OPENSSL_LIBRARIES} Threads::Threads)
target_link_libraries(client OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
target_link_libraries(client /opt/homebrew/lib/libjsoncpp.dylib)  # Link jsoncpp