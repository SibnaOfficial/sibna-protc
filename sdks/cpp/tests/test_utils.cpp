#include <catch2/catch_test_macros.hpp>
#include <sibna/utils.hpp>
#include <sibna/types.hpp>

using namespace sibna;

TEST_CASE("Utils::random_bytes produces correct length", "[utils]") {
    bytes result = Utils::random_bytes(32);
    REQUIRE(result.size() == 32);
}

TEST_CASE("Utils::random_bytes produces unique values", "[utils]") {
    bytes r1 = Utils::random_bytes(32);
    bytes r2 = Utils::random_bytes(32);
    REQUIRE(r1 != r2);
}

TEST_CASE("Utils::bytes_to_hex and hex_to_bytes roundtrip", "[utils]") {
    bytes original = {0x00, 0x01, 0x02, 0x0A, 0xFF};
    std::string hex = Utils::bytes_to_hex(original);
    bytes decoded = Utils::hex_to_bytes(hex);
    REQUIRE(decoded == original);
}

TEST_CASE("Utils::bytes_to_hex produces correct output", "[utils]") {
    bytes data = {0xDE, 0xAD, 0xBE, 0xEF};
    std::string hex = Utils::bytes_to_hex(data);
    REQUIRE(hex == "deadbeef");
}

TEST_CASE("Utils::base64 roundtrip", "[utils]") {
    bytes original = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
    std::string b64 = Utils::bytes_to_base64(original);
    bytes decoded = Utils::base64_to_bytes(b64);
    REQUIRE(decoded == original);
}

TEST_CASE("Utils::secure_clear zeros memory", "[utils]") {
    bytes data = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
    Utils::secure_clear(data);
    for (byte b : data) {
        REQUIRE(b == 0);
    }
}

TEST_CASE("Utils::constant_time_equals", "[utils]") {
    bytes a = {0x01, 0x02, 0x03};
    bytes b = {0x01, 0x02, 0x03};
    bytes c = {0x01, 0x02, 0x04};

    REQUIRE(Utils::constant_time_equals(a, b));
    REQUIRE_FALSE(Utils::constant_time_equals(a, c));
}

TEST_CASE("Utils::constant_time_equals rejects different lengths", "[utils]") {
    bytes a = {0x01, 0x02};
    bytes b = {0x01, 0x02, 0x03};

    REQUIRE_FALSE(Utils::constant_time_equals(a, b));
}

TEST_CASE("Utils::constant_time_equals with fixed arrays", "[utils]") {
    std::array<byte, 32> a = Utils::random_bytes<32>();
    std::array<byte, 32> b = a;
    std::array<byte, 32> c = Utils::random_bytes<32>();

    REQUIRE(Utils::constant_time_equals(a, b));
    REQUIRE_FALSE(Utils::constant_time_equals(a, c));
}
