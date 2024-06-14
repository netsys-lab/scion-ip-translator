cmake_minimum_required(VERSION 3.22)

project(xdp-sock-prog C)

set(CMAKE_C_COMPILER clang)

add_library(af_xdp_obj OBJECT
    af_xdp.c
)
target_compile_options(af_xdp_obj PRIVATE
    -O3 -g -target bpf --std gnu17 -Wall -Wextra -Wpedantic
    -Wno-pointer-arith -Wno-gnu-zero-variadic-macro-arguments
)
target_compile_definitions(af_xdp_obj PRIVATE DEBUG)

add_custom_target(af_xdp ALL DEPENDS af_xdp.c.o)
add_dependencies(af_xdp af_xdp_obj)
add_custom_command(
    OUTPUT af_xdp.c.o
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_OBJECTS:af_xdp_obj>"
    ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND_EXPAND_LISTS
    DEPENDS "$<TARGET_OBJECTS:af_xdp_obj>"
)
