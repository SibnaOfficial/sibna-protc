#include <catch2/catch_test_macros.hpp>
#include <sibna/session.hpp>
#include <sibna/context.hpp>
#include <sibna/types.hpp>

using namespace sibna;

TEST_CASE("Session creation", "[session]") {
    bytes peer_id = Utils::random_bytes(32);
    Session session(peer_id, nullptr);

    REQUIRE(session.peer_id() == peer_id);
    REQUIRE_FALSE(session.is_established());
    REQUIRE(session.current_message_number() == 0);
}

TEST_CASE("Session encrypt and decrypt", "[session]") {
    bytes peer_id = Utils::random_bytes(32);
    Session session(peer_id, nullptr);

    bytes plaintext = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
    bytes aad = {};

    auto encrypted = session.encrypt(plaintext, aad);
    REQUIRE(encrypted.is_ok());
    REQUIRE(encrypted.value().size() > plaintext.size());

    auto decrypted = session.decrypt(encrypted.value(), aad);
    REQUIRE(decrypted.is_ok());
    REQUIRE(decrypted.value() == plaintext);
}

TEST_CASE("Session encrypt increments message count", "[session]") {
    bytes peer_id = Utils::random_bytes(32);
    Session session(peer_id, nullptr);

    bytes plaintext = {0x01};

    session.encrypt(plaintext, {});
    REQUIRE(session.current_message_number() == 1);

    session.encrypt(plaintext, {});
    REQUIRE(session.current_message_number() == 2);
}

TEST_CASE("Session encrypt fails with empty plaintext", "[session]") {
    bytes peer_id = Utils::random_bytes(32);
    Session session(peer_id, nullptr);

    bytes empty;
    auto result = session.encrypt(empty, {});
    REQUIRE(result.is_err());
    REQUIRE(result.code() == ResultCode::INVALID_ARGUMENT);
}

TEST_CASE("Session rejects ciphertext too short", "[session]") {
    bytes peer_id = Utils::random_bytes(32);
    Session session(peer_id, nullptr);

    bytes short_ct = {0x01, 0x02};
    auto result = session.decrypt(short_ct, {});
    REQUIRE(result.is_err());
    REQUIRE(result.code() == ResultCode::INVALID_CIPHERTEXT);
}

TEST_CASE("Session get_stats", "[session]") {
    bytes peer_id = Utils::random_bytes(32);
    Session session(peer_id, nullptr);

    auto info = session.get_stats();
    REQUIRE(info.peer_id == peer_id);
    REQUIRE(info.messages_sent == 0);
    REQUIRE(info.messages_received == 0);
    REQUIRE_FALSE(info.is_established);
}
