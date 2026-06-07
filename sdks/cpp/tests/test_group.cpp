#include <catch2/catch_test_macros.hpp>
#include <sibna/group.hpp>
#include <sibna/types.hpp>

using namespace sibna;

TEST_CASE("GroupSession creation", "[group]") {
    group_id gid;
    std::fill(gid.begin(), gid.end(), 0x01);

    GroupSession group(gid);
    REQUIRE(group.id() == gid);
}

TEST_CASE("GroupSession add member", "[group]") {
    group_id gid;
    std::fill(gid.begin(), gid.end(), 0x01);

    GroupSession group(gid);
    std::array<byte, 32> member = Utils::random_bytes<KEY_LENGTH>();
    auto result = group.add_member(member);
    REQUIRE(result.is_ok());
    REQUIRE(group.member_count() == 1);
}

TEST_CASE("GroupSession encrypt and decrypt", "[group]") {
    group_id gid;
    std::fill(gid.begin(), gid.end(), 0x01);

    GroupSession group(gid);
    
    // Need at least one member to encrypt
    std::array<byte, 32> member = Utils::random_bytes<KEY_LENGTH>();
    auto add_result = group.add_member(member);
    REQUIRE(add_result.is_ok());

    // Generate a sender key
    auto key_result = Crypto::generate_key();
    REQUIRE(key_result.is_ok());
    
    // Import the sender key for the member
    auto import_result = group.import_sender_key(member, key_result.value());
    REQUIRE(import_result.is_ok());

    bytes plaintext = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
    auto encrypted = group.encrypt(plaintext);
    REQUIRE(encrypted.is_ok());

    auto decrypted = group.decrypt(encrypted.value(), member);
    REQUIRE(decrypted.is_ok());
    REQUIRE(decrypted.value() == plaintext);
}

TEST_CASE("GroupSession encrypt fails with empty plaintext", "[group]") {
    group_id gid;
    std::fill(gid.begin(), gid.end(), 0x01);

    GroupSession group(gid);
    std::array<byte, 32> member = Utils::random_bytes<KEY_LENGTH>();
    group.add_member(member);

    bytes empty;
    auto result = group.encrypt(empty);
    REQUIRE(result.is_err());
    REQUIRE(result.code() == ResultCode::INVALID_ARGUMENT);
}

TEST_CASE("GroupSession encrypt fails without members", "[group]") {
    group_id gid;
    std::fill(gid.begin(), gid.end(), 0x01);

    GroupSession group(gid);

    bytes plaintext = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
    auto result = group.encrypt(plaintext);
    REQUIRE(result.is_err());
    REQUIRE(result.code() == ResultCode::INVALID_STATE);
}

TEST_CASE("GroupSession get_info", "[group]") {
    group_id gid;
    std::fill(gid.begin(), gid.end(), 0x01);

    GroupSession group(gid);
    auto info = group.get_info();
    REQUIRE(info.id == gid);
    REQUIRE(info.member_count == 0);
}
