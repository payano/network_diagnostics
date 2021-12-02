cmake_minimum_required(VERSION 3.10)

#set(CMAKE_BUILD_TYPE Debug)
#set(THREADS_PREFER_PTHREAD_FLAG ON)

#set(CMAKE_CXX_FLAGS "-Wall -std=c++0x -pedantic -O2 -Werror -Wextra -fexceptions")
#set(CMAKE_CC_FLAGS "-Wall -pedantic -O2 -Werror -Wextra -fexceptions -std=c99")
#set(CMAKE_C_FLAGS "-Wall -pedantic -O2 -Werror -Wextra -fexceptions")
set(CMAKE_CXX_FLAGS "-Wall -pedantic -O2 -Werror -Wextra -fexceptions -D_GNU_SOURCE")

#add_definitions("-D_GNU_SOURCE=1")

#set(CMAKE_CXX_STANDARD 14)
#set(CMAKE_CXX_STANDARD_REQUIRED ON)

project (network_tester)
find_package (Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(FLEX REQUIRED)

include_directories(src)

macro(print_all_variables)
    message(STATUS "print_all_variables------------------------------------------{")
    get_cmake_property(_variableNames VARIABLES)
    foreach (_variableName ${_variableNames})
        message(STATUS "${_variableName}=${${_variableName}}")
    endforeach()
    message(STATUS "print_all_variables------------------------------------------}")
endmacro()

set(DISABLE_DBUS ON)
option(DISABLE_DBUS "Disable D-Bus sniffing support" ON)
add_subdirectory(ext/libpcap)
#add_library(pcap STATIC IMPORTED)


message(STATUS "include dir: ${CMAKE_CXX_FLAGS}")

#print_all_variables()
############################################################
# Create an executable
############################################################

# Add an executable with the above sources
add_executable(
  network_tester
  src/client.c
  src/main.c
  src/receiver.c
  src/pcap_helper.c
  src/listener.c
  src/print.c

)
target_link_libraries(network_tester ${pcap_BINARY_DIR}/libpcap.a)

add_dependencies(network_tester pcap_static)
include_directories(${CMAKE_SOURCE_DIR}/ext/libpcap)
#google test
#include_directories(cmake-build-debug/test/gtest/src/gtest/googletest/include)
#add_subdirectory(test)
