cmake_minimum_required(VERSION 3.22)
include(FetchContent)
include(ExternalProject)

find_program(MAKE NAMES make)

project(SCION_IPv6_Translation VERSION 0.1 LANGUAGES C CXX)
list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

# Mixing C++ versions results in UB, hence we declare it globally
set_property(GLOBAL PROPERTY CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

FetchContent_Declare(
    snet-bindings
    GIT_REPOSITORY https://github.com/lschulz/snet-bindings
    GIT_TAG f9e1c80e9688b8acfe5061be081c96c4a9ae5a1b
)

set(BUILD_EXAMPLES OFF)
set(BUILD_SHARED_LIBS ON)
FetchContent_MakeAvailable(snet-bindings)

ExternalProject_Add(libbpf
    PREFIX libbpf
    GIT_REPOSITORY https://github.com/libbpf/libbpf
    GIT_TAG 445486dcbf9ddd8b3ca799a98ace58d23cee31a1
    CONFIGURE_COMMAND ""
    BUILD_IN_SOURCE TRUE
    BUILD_COMMAND ${MAKE} -C src
    INSTALL_COMMAND ""
)

ExternalProject_Add(bpftool
    PREFIX bpftool
    GIT_REPOSITORY https://github.com/libbpf/bpftool
    GIT_TAG 22621e39da611c292b7c13d89af7bdccc7b905fb
    CONFIGURE_COMMAND ""
    BUILD_IN_SOURCE TRUE
    BUILD_COMMAND ${MAKE} -C src
    INSTALL_COMMAND ""
)

set(BPFOBJECT_VMLINUX_H ${CMAKE_CURRENT_SOURCE_DIR}/vmlinux/vmlinux.h)
set(BPFOBJECT_BPFTOOL ${CMAKE_BINARY_DIR}/bpftool/src/bpftool/src/bootstrap/bpftool)
set(LIBBPF_LIBRARIES ${CMAKE_BINARY_DIR}/libbpf/src/libbpf/src/libbpf.a)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_BINARY_DIR}/libbpf/src/libbpf)

find_package(BpfObject REQUIRED)

# Build object skeletons and depend skeleton on libbpf build
bpf_object(ingress bpf/ingress.bpf.c)
add_dependencies(ingress_skel libbpf-build bpftool-build)

bpf_object(egress bpf/egress.bpf.c)
add_dependencies(egress_skel libbpf-build bpftool-build)

# Configure final bundled executable
add_executable(loader)
target_include_directories(loader PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/include)
target_include_directories(loader PRIVATE BEFORE SYSTEM
    ${CMAKE_BINARY_DIR}/libbpf/src/libbpf/src
)
target_link_libraries(loader INTERFACE libbpf-build)
target_link_libraries(loader PRIVATE egress_skel ingress_skel snet_cpp)
set_target_properties(loader PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF)
add_subdirectory(src)
