cmake_minimum_required(VERSION 3.14)
project(sibna_protocol VERSION 1.0.0 LANGUAGES CXX)

# C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Options
option(SIBNA_BUILD_TESTS "Build tests" ON)
option(SIBNA_BUILD_EXAMPLES "Build examples" ON)
option(SIBNA_BUILD_SHARED "Build shared library" ON)
option(SIBNA_ENABLE_ASAN "Enable AddressSanitizer" OFF)

# Compiler flags
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Werror=return-type
        -Werror=uninitialized
        -Werror=unused-result
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2
    )
    
    if(SIBNA_ENABLE_ASAN)
        add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
    endif()
endif()

if(MSVC)
    add_compile_options(
        /W4
        /WX-
        /permissive-
        /sdl
        /guard:cf
        /DYNAMICBASE
        /NXCOMPAT
    )
endif()

# Find dependencies
find_package(Threads REQUIRED)

# Library type
if(SIBNA_BUILD_SHARED)
    set(SIBNA_LIBRARY_TYPE SHARED)
else()
    set(SIBNA_LIBRARY_TYPE STATIC)
endif()

# Source files
set(SIBNA_SOURCES
    src/context.cpp
    src/session.cpp
    src/crypto.cpp
    src/identity.cpp
    src/group.cpp
    src/safety_number.cpp
    src/utils.cpp
    src/error.cpp
)

set(SIBNA_HEADERS
    include/sibna/sibna.hpp
    include/sibna/context.hpp
    include/sibna/session.hpp
    include/sibna/crypto.hpp
    include/sibna/identity.hpp
    include/sibna/group.hpp
    include/sibna/safety_number.hpp
    include/sibna/utils.hpp
    include/sibna/error.hpp
    include/sibna/types.hpp
)

# Create library
add_library(sibna_protocol ${SIBNA_LIBRARY_TYPE} ${SIBNA_SOURCES})

target_include_directories(sibna_protocol
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(sibna_protocol
    PUBLIC
        Threads::Threads
)

# Set library version
set_target_properties(sibna_protocol PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    OUTPUT_NAME sibna
)

# Tests
if(SIBNA_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Examples
if(SIBNA_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Installation
include(GNUInstallDirs)

install(TARGETS sibna_protocol
    EXPORT sibna_protocol-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(FILES ${SIBNA_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/sibna
)

install(EXPORT sibna_protocol-targets
    FILE sibna_protocol-targets.cmake
    NAMESPACE sibna::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sibna_protocol
)

# Package configuration
include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/sibna_protocol-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/sibna_protocol-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sibna_protocol
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/sibna_protocol-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/sibna_protocol-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/sibna_protocol-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sibna_protocol
)

# Print configuration
message(STATUS "Sibna Protocol v${PROJECT_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Library type: ${SIBNA_LIBRARY_TYPE}")
message(STATUS "  Build tests: ${SIBNA_BUILD_TESTS}")
message(STATUS "  Build examples: ${SIBNA_BUILD_EXAMPLES}")
message(STATUS "  AddressSanitizer: ${SIBNA_ENABLE_ASAN}")
