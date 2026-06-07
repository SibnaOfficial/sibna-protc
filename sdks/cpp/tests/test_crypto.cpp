#include <catch2/catch_test_macros.hpp>
#include <sibna/crypto.hpp>
#include <sibna/types.hpp>

using namespace sibna;

TEST_CASE("Crypto::encrypt and decrypt roundtrip", "[crypto]") {
    key k = Utils::random_bytes<KEY_LENGTH>();
    bytes plaintext = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
    bytes aad = {0x01, 0x02};

    auto encrypted = Crypto::encrypt(k, plaintext, aad);
    REQUIRE(encrypted.is_ok());

    auto decrypted = Crypto::decrypt(k, encrypted.value(), aad);
    REQUIRE(decrypted.is_ok());
    REQUIRE(decrypted.value() == plaintext);
}

TEST_CASE("Crypto::encrypt fails with wrong key", "[crypto]") {
    key k1 = Utils::random_bytes<KEY_LENGTH>();
    key k2 = Utils::random_bytes<KEY_LENGTH>();
    bytes plaintext = {0x48, 0x65, 0x6C, 0x6C, 0x6F};

    auto encrypted = Crypto::encrypt(k1, plaintext, {});
    REQUIRE(encrypted.is_ok());

    auto decrypted = Crypto::decrypt(k2, encrypted.value(), {});
    REQUIRE(decrypted.is_err());
}

TEST_CASE("Crypto::decrypt fails with wrong AAD", "[crypto]") {
    key k = Utils::random_bytes<KEY_LENGTH>();
    bytes plaintext = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
    bytes aad1 = {0x01};
    bytes aad2 = {0x02};

    auto encrypted = Crypto::encrypt(k, plaintext, aad1);
    REQUIRE(encrypted.is_ok());

    auto decrypted = Crypto::decrypt(k, encrypted.value(), aad2);
    REQUIRE(decrypted.is_err());
}

TEST_CASE("Crypto::decrypt fails with tampered ciphertext", "[crypto]") {
    key k = Utils::random_bytes<KEY_LENGTH>();
    bytes plaintext = {0x48, 0x65, 0x6C, 0x6C, 0x6F};

    auto encrypted = Crypto::encrypt(k, plaintext, {});
    REQUIRE(encrypted.is_ok());

    bytes tampered = encrypted.value();
    REQUIRE(tampered.size() > 0);
    tampered[0] ^= 0xFF;

    auto decrypted = Crypto::decrypt(k, tampered, {});
    REQUIRE(decrypted.is_err());
}

TEST_CASE("Crypto::encrypt rejects empty key", "[crypto]") {
    key k{};
    bytes plaintext = {0x01};

    auto result = Crypto::encrypt(k, plaintext, {});
    REQUIRE(result.is_ok());
}

TEST_CASE("Pad and unpad roundtrip", "[crypto]") {
    bytes data = {0x48, 0x65, 0x6C, 0x6C, 0x6F};

    auto padded = Crypto::pad(data);
    REQUIRE(padded.is_ok());
    REQUIRE(padded.value().size() >= data.size());
    REQUIRE(padded.value().size() % 1024 == 0);

    auto unpadded = Crypto::unpad(padded.value());
    REQUIRE(unpadded.is_ok());
    REQUIRE(unpadded.value() == data);
}

TEST_CASE("Pad and unpad large data", "[crypto]") {
    bytes data(5000, 0xAA);

    auto padded = Crypto::pad(data);
    REQUIRE(padded.is_ok());

    auto unpadded = Crypto::unpad(padded.value());
    REQUIRE(unpadded.is_ok());
    REQUIRE(unpadded.value() == data);
}

TEST_CASE("Unpad empty data fails", "[crypto]") {
    bytes empty;
    auto result = Crypto::unpad(empty);
    REQUIRE(result.is_err());
}
