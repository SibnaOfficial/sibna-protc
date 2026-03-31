cmake_minimum_required(VERSION 3.14)

# Sibna Flutter Plugin — Windows build
# The plugin uses dart:ffi so no MethodChannel plumbing is needed.
# This file configures how sibna.dll is bundled with the Flutter app.

project(sibna_flutter_plugin VERSION 1.0.0 LANGUAGES CXX)

set(PLUGIN_NAME sibna_flutter_plugin)

# Plugin stub (empty — dart:ffi handles everything)
add_library(${PLUGIN_NAME} INTERFACE)

# Bundle sibna.dll next to the Flutter executable
# Expected location: windows/sibna.dll (pre-built Rust release)
set(SIBNA_DLL_PATH "${CMAKE_CURRENT_SOURCE_DIR}/sibna.dll")

if(EXISTS "${SIBNA_DLL_PATH}")
    install(
        FILES "${SIBNA_DLL_PATH}"
        DESTINATION "${CMAKE_INSTALL_PREFIX}"
    )
    message(STATUS "Sibna: bundling sibna.dll from ${SIBNA_DLL_PATH}")
else()
    message(WARNING
        "sibna.dll not found at ${SIBNA_DLL_PATH}. "
        "Build it with: cargo build --release --features ffi --target x86_64-pc-windows-msvc"
    )
endif()
