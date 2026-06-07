#include <catch2/catch_test_macros.hpp>
#include <sibna/context.hpp>
#include <sibna/types.hpp>

using namespace sibna;

TEST_CASE("Context creation without password", "[context]") {
    Config config;
    auto result = Context::create(config);
    REQUIRE(result.is_ok());
}

TEST_CASE("Context creation with password", "[context]") {
    Config config;
    auto result = Context::create(config, "test_password_123");
    REQUIRE(result.is_ok());
}

TEST_CASE("Context generate identity", "[context]") {
    Config config;
    auto ctx = Context::create(config);
    REQUIRE(ctx.is_ok());

    auto identity = ctx.value()->generate_identity();
    REQUIRE(identity.is_ok());
    REQUIRE(identity.value().ed25519_public_key().size() == KEY_LENGTH);
}

TEST_CASE("Context create session", "[context]") {
    Config config;
    auto ctx = Context::create(config);
    REQUIRE(ctx.is_ok());

    ctx.value()->generate_identity();

    bytes peer_id = Utils::random_bytes(32);
    auto session = ctx.value()->create_session(peer_id);
    REQUIRE(session.is_ok());
}

TEST_CASE("Context encrypt and decrypt", "[context]") {
    Config config;
    auto ctx = Context::create(config);
    REQUIRE(ctx.is_ok());

    ctx.value()->generate_identity();

    bytes peer_id = Utils::random_bytes(32);
    auto session = ctx.value()->create_session(peer_id);
    REQUIRE(session.is_ok());

    bytes plaintext = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
    auto encrypted = ctx.value()->encrypt_message(peer_id, plaintext, {});
    REQUIRE(encrypted.is_ok());

    auto decrypted = ctx.value()->decrypt_message(peer_id, encrypted.value(), {});
    REQUIRE(decrypted.is_ok());
    REQUIRE(decrypted.value() == plaintext);
}

TEST_CASE("Context encrypt fails without session", "[context]") {
    Config config;
    auto ctx = Context::create(config);
    REQUIRE(ctx.is_ok());

    bytes peer_id = Utils::random_bytes(32);
    bytes plaintext = {0x01};
    auto result = ctx.value()->encrypt_message(peer_id, plaintext, {});
    REQUIRE(result.is_err());
    REQUIRE(result.code() == ResultCode::SESSION_NOT_FOUND);
}

TEST_CASE("Context get_stats", "[context]") {
    Config config;
    auto ctx = Context::create(config);
    REQUIRE(ctx.is_ok());

    auto stats = ctx.value()->get_stats();
    REQUIRE(stats.is_ok());
    REQUIRE(stats.value().session_count == 0);
    REQUIRE(stats.value().group_count == 0);
    REQUIRE(stats.value().version == VERSION_STRING);
}

TEST_CASE("Context create group", "[context]") {
    Config config;
    auto ctx = Context::create(config);
    REQUIRE(ctx.is_ok());

    group_id gid;
    std::fill(gid.begin(), gid.end(), 0x01);

    auto group = ctx.value()->create_group(gid);
    REQUIRE(group.is_ok());
}

TEST_CASE("Context duplicate group rejected", "[context]") {
    Config config;
    auto ctx = Context::create(config);
    REQUIRE(ctx.is_ok());

    group_id gid;
    std::fill(gid.begin(), gid.end(), 0x01);

    auto g1 = ctx.value()->create_group(gid);
    REQUIRE(g1.is_ok());

    auto g2 = ctx.value()->create_group(gid);
    REQUIRE(g2.is_err());
    REQUIRE(g2.code() == ResultCode::INVALID_ARGUMENT);
}
