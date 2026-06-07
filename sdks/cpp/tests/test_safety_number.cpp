#include <catch2/catch_test_macros.hpp>
#include <sibna/safety_number.hpp>
#include <sibna/types.hpp>

using namespace sibna;

TEST_CASE("SafetyNumber calculate", "[safety]") {
    std::array<byte, 32> key1 = Utils::random_bytes<KEY_LENGTH>();
    std::array<byte, 32> key2 = Utils::random_bytes<KEY_LENGTH>();

    auto sn = SafetyNumber::calculate(key1, key2);
    REQUIRE(sn.is_ok());
    REQUIRE_FALSE(sn.value().formatted_number().empty());
}

TEST_CASE("SafetyNumber is symmetric", "[safety]") {
    std::array<byte, 32> key1 = Utils::random_bytes<KEY_LENGTH>();
    std::array<byte, 32> key2 = Utils::random_bytes<KEY_LENGTH>();

    auto sn1 = SafetyNumber::calculate(key1, key2);
    auto sn2 = SafetyNumber::calculate(key2, key1);
    REQUIRE(sn1.is_ok());
    REQUIRE(sn2.is_ok());
    REQUIRE(sn1.value().verify(sn2.value()));
}

TEST_CASE("SafetyNumber differs for different keys", "[safety]") {
    std::array<byte, 32> key1 = Utils::random_bytes<KEY_LENGTH>();
    std::array<byte, 32> key2 = Utils::random_bytes<KEY_LENGTH>();
    std::array<byte, 32> key3 = Utils::random_bytes<KEY_LENGTH>();

    auto sn1 = SafetyNumber::calculate(key1, key2);
    auto sn2 = SafetyNumber::calculate(key1, key3);
    REQUIRE(sn1.is_ok());
    REQUIRE(sn2.is_ok());
    REQUIRE_FALSE(sn1.value().verify(sn2.value()));
}

TEST_CASE("SafetyNumber formatted output", "[safety]") {
    std::array<byte, 32> key1 = Utils::random_bytes<KEY_LENGTH>();
    std::array<byte, 32> key2 = Utils::random_bytes<KEY_LENGTH>();

    auto sn = SafetyNumber::calculate(key1, key2);
    REQUIRE(sn.is_ok());

    std::string formatted = sn.value().formatted_number();
    REQUIRE_FALSE(formatted.empty());
    // Should contain only digits and spaces
    for (char c : formatted) {
        REQUIRE((std::isdigit(c) || c == ' '));
    }
}

TEST_CASE("SafetyNumber parse and roundtrip", "[safety]") {
    std::array<byte, 32> key1 = Utils::random_bytes<KEY_LENGTH>();
    std::array<byte, 32> key2 = Utils::random_bytes<KEY_LENGTH>();

    auto sn = SafetyNumber::calculate(key1, key2);
    REQUIRE(sn.is_ok());

    std::string formatted = sn.value().formatted_number();
    auto parsed = SafetyNumber::parse(formatted);
    REQUIRE(parsed.is_ok());
    REQUIRE(parsed.value().verify(sn.value()));
}
