#include <catch2/catch_test_macros.hpp>
#include <sibna/identity.hpp>
#include <sibna/types.hpp>

using namespace sibna;

TEST_CASE("IdentityKeyPair::generate produces valid keys", "[identity]") {
    auto result = IdentityKeyPair::generate();
    REQUIRE(result.is_ok());

    auto identity = std::move(result).value();
    REQUIRE(identity.ed25519_public_key().size() == KEY_LENGTH);
    REQUIRE(identity.x25519_public_key().size() == KEY_LENGTH);
}

TEST_CASE("IdentityKeyPair::generate produces unique keys", "[identity]") {
    auto r1 = IdentityKeyPair::generate();
    auto r2 = IdentityKeyPair::generate();
    REQUIRE(r1.is_ok());
    REQUIRE(r2.is_ok());

    REQUIRE(r1.value().ed25519_public_key() != r2.value().ed25519_public_key());
}

TEST_CASE("IdentityKeyPair sign and verify", "[identity]") {
    auto result = IdentityKeyPair::generate();
    REQUIRE(result.is_ok());
    auto identity = std::move(result).value();

    bytes data = {0x01, 0x02, 0x03, 0x04, 0x05};
    auto sig = identity.sign(data);
    REQUIRE(sig.is_ok());
    REQUIRE(sig.value().size() == SIGNATURE_LENGTH);

    auto verified = identity.verify(data, sig.value());
    REQUIRE(verified.is_ok());
    REQUIRE(verified.value());
}

TEST_CASE("IdentityKeyPair verify rejects tampered signature", "[identity]") {
    auto result = IdentityKeyPair::generate();
    REQUIRE(result.is_ok());
    auto identity = std::move(result).value();

    bytes data = {0x01, 0x02, 0x03, 0x04, 0x05};
    auto sig = identity.sign(data);
    REQUIRE(sig.is_ok());

    signature tampered = sig.value();
    tampered[0] ^= 0xFF;
    auto verified = identity.verify(data, tampered);
    REQUIRE(verified.is_ok());
    REQUIRE_FALSE(verified.value());
}

TEST_CASE("IdentityKeyPair verify rejects wrong data", "[identity]") {
    auto result = IdentityKeyPair::generate();
    REQUIRE(result.is_ok());
    auto identity = std::move(result).value();

    bytes data = {0x01, 0x02, 0x03};
    bytes wrong_data = {0x04, 0x05, 0x06};
    auto sig = identity.sign(data);
    REQUIRE(sig.is_ok());

    auto verified = identity.verify(wrong_data, sig.value());
    REQUIRE(verified.is_ok());
    REQUIRE_FALSE(verified.value());
}

TEST_CASE("IdentityKeyPair fingerprint", "[identity]") {
    auto result = IdentityKeyPair::generate();
    REQUIRE(result.is_ok());

    std::string fp = result.value().fingerprint();
    REQUIRE_FALSE(fp.empty());
}
