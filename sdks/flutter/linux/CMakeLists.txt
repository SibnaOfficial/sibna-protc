cmake_minimum_required(VERSION 3.14)

project(sibna_flutter_plugin VERSION 1.0.0 LANGUAGES CXX)

set(PLUGIN_NAME sibna_flutter_plugin)
add_library(${PLUGIN_NAME} INTERFACE)

# Bundle libsibna.so next to the Flutter executable
set(SIBNA_SO_PATH "${CMAKE_CURRENT_SOURCE_DIR}/libsibna.so")

if(EXISTS "${SIBNA_SO_PATH}")
    install(
        FILES "${SIBNA_SO_PATH}"
        DESTINATION "${CMAKE_INSTALL_PREFIX}/lib"
    )
else()
    message(WARNING
        "libsibna.so not found. "
        "Build: cargo build --release --features ffi --target x86_64-unknown-linux-gnu"
    )
endif()
