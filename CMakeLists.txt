cmake_minimum_required (VERSION 3.10)
project(rust_c_examples VERSION 0.1.0)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/dep/cmake-cargo/cmake")
set(CARGO_DEV_MODE ON CACHE INTERNAL "")

include(Cargo)

add_crate(dep/rusctp/Cargo.toml)

add_subdirectory(dep/libuv)

include_directories("${CMAKE_SOURCE_DIR}/dep/rusctp/include")
include_directories("${CMAKE_SOURCE_DIR}/dep/libuv/include")

add_executable(client client.c)
target_link_libraries(client PUBLIC rusctp)

add_executable(server server.c)
target_link_libraries(server PUBLIC ws2_32 uv_a rusctp)