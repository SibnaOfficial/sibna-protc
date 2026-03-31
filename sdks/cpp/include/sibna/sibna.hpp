#pragma once

// Main header file for Sibna Protocol C++ SDK

#include "types.hpp"
#include "error.hpp"
#include "utils.hpp"
#include "crypto.hpp"
#include "identity.hpp"
#include "session.hpp"
#include "group.hpp"
#include "safety_number.hpp"
#include "context.hpp"

namespace sibna {

// Version information
constexpr const char* version() {
    return VERSION_STRING;
}

constexpr uint32_t protocol_version() {
    return PROTOCOL_VERSION;
}

constexpr uint32_t min_compatible_version() {
    return MIN_COMPATIBLE_VERSION;
}

} // namespace sibna

// Convenience macros
#define SIBNA_VERSION sibna::version()
#define SIBNA_PROTOCOL_VERSION sibna::protocol_version()
#define SIBNA_MIN_COMPATIBLE_VERSION sibna::min_compatible_version()
