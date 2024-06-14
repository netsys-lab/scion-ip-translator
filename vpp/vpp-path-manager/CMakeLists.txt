cmake_minimum_required(VERSION 3.22)
include(FetchContent)
include(ExternalProject)

FetchContent_Declare(asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio
    GIT_TAG asio-1-30-2
    GIT_SHALLOW 1
)
FetchContent_Declare(spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog
    GIT_TAG v1.14.1
    GIT_SHALLOW 1
)
FetchContent_Declare(tomlplusplus
    GIT_REPOSITORY https://github.com/marzer/tomlplusplus
    GIT_TAG v3.4.0
    GIT_SHALLOW 1
)

FetchContent_MakeAvailable(asio spdlog tomlplusplus)

find_program(MAKE NAMES make)
ExternalProject_Add(libbpf
    GIT_REPOSITORY https://github.com/libbpf/libbpf
    GIT_TAG v1.4.2
    GIT_SHALLOW 1
    CONFIGURE_COMMAND ""
    BUILD_IN_SOURCE 1
    BUILD_COMMAND ${MAKE} -C src
    INSTALL_COMMAND ""
)

add_subdirectory(bpf)

project(vpp-path-manager C CXX)

set(VPP_INCLUDE "~/vpp/build-root/install-vpp_debug-native/vpp/include" CACHE PATH "VPP include path")
set(VPP_LIB "~/vpp/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu" CACHE PATH "VPP library path")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)

add_library(vapi SHARED IMPORTED)
set_target_properties(vapi PROPERTIES
    IMPORTED_LOCATION ${VPP_LIB}/libvapiclient.so
    INTERFACE_INCLUDE_DIRECTORIES ${VPP_INCLUDE}
)

add_library(libbpf-import SHARED IMPORTED)
ExternalProject_Get_Property(libbpf SOURCE_DIR)
set_target_properties(libbpf-import PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/src/libbpf.so
    INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/src
)

set(SRC
    src/main.cpp
    src/config.cpp
    src/dataplane.cpp
    src/netlink.cpp
    src/ebpf.cpp
)

add_executable(path-manager ${SRC})
add_dependencies(path-manager af_xdp)
target_include_directories(path-manager PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/scion/include)
target_link_libraries(path-manager vapi spdlog tomlplusplus::tomlplusplus)
target_link_libraries(path-manager libbpf-import -lmnl)
