use futures_util::{SinkExt, StreamExt};
use hex;
use jsonwebtoken::{encode, EncodingKey, Header};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sibna_core::{Config, SecureContext};
use sibna_server::run_server;
use std::net::SocketAddr;
use std::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    iat: i64,
    exp: i64,
    device: String,
}

fn create_mock_jwt(id: &str, secret: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = Claims {
        sub: id.to_string(),
        iat: now,
        exp: now + 3600,
        device: "test_device".to_string(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

async fn spawn_test_server(jwt_secret: &str) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Use the OS temp directory for the redb database so tests work
    // consistently across Windows, Linux, and macOS. redb requires the parent
    // directory to exist; temp_dir() always provides a valid, writable location.
    let db_path = std::env::temp_dir()
        .join(format!("sibna_test_db_{}", uuid::Uuid::new_v4()))
        .to_string_lossy()
        .to_string();

    // Set secret in env for the server to pick up
    std::env::set_var("SIBNA_JWT_SECRET", jwt_secret);

    tokio::spawn(async move {
        if let Err(e) = run_server(listener, Some(db_path)).await {
            eprintln!("SERVER_ERROR: {}", e);
        }
    });

    // Wait for server to be ready by polling health endpoint
    let client = reqwest::Client::new();
    let health_url = format!("http://{}/health", addr);
    for _ in 0..60 {
        if let Ok(resp) = reqwest::get(&health_url).await {
            if resp.status().is_success() {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Additional check: verify JWT auth works by trying to authenticate
    let test_ctx = SecureContext::new(Config::default(), None).unwrap();
    test_ctx.generate_identity().unwrap();
    let test_id = test_ctx.get_identity().unwrap().ed25519_public;
    let test_id_hex = hex::encode(test_id);
    let test_token = create_mock_jwt(&test_id_hex, jwt_secret);
    let test_url = format!("http://{}/v1/messages/send", addr);
    let test_req = json!({
        "recipient_id": hex::encode(&[0u8; 32]),
        "payload_hex": "deadbeef",
        "compressed": false,
    });
    let test_client = reqwest::Client::new();
    for _ in 0..30 {
        if let Ok(test_resp) = test_client
            .post(&format!("http://{}/v1/messages/send", addr))
            .header("Authorization", format!("Bearer {}", test_token))
            .json(&json!({
                "recipient_id": hex::encode(&[0u8; 32]),
                "payload_hex": "deadbeef",
                "compressed": false,
            }))
            .send()
            .await
        {
            if test_resp.status().is_success()
                || test_resp.status() == reqwest::StatusCode::ACCEPTED
            {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    addr
}

#[tokio::test]
async fn test_aggressive_zombi_ws_flood() {
    let secret = "test_aggressive_secret";
    let addr = spawn_test_server(secret).await;

    let mut connections = Vec::new();
    for i in 0..50 {
        let id = format!("{:064x}", i);
        let token = create_mock_jwt(&id, secret);
        let ws_url = format!("ws://{}/ws?token={}", addr, token);

        if let Ok((ws_stream, _)) = connect_async(&ws_url).await {
            connections.push(ws_stream);
        }
    }

    println!(
        "Opened {} active authenticated connections",
        connections.len()
    );

    // Attack: Send garbage to one connection
    if let Some(mut first) = connections.pop() {
        first
            .send(Message::Binary(vec![0xDE, 0xAD, 0xBE, 0xEF]))
            .await
            .ok();
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn test_aggressive_json_bomb_protection() {
    let secret = "test_bomb_secret";
    let addr = spawn_test_server(secret).await;
    let client = Client::new();
    let url = format!("http://{}/v1/messages/send", addr);

    // Limit is 21MB. Let's send a 22MB payload.
    let huge_payload = "A".repeat(22 * 1024 * 1024);
    let bomb = json!({
        "recipient_id": "0".repeat(64),
        "payload_hex": huge_payload,
        "message_id": "bomb_id"
    });

    match client
        .post(&url)
        .header(
            "Authorization",
            format!("Bearer {}", create_mock_jwt("alice", secret)),
        )
        .json(&bomb)
        .send()
        .await
    {
        Ok(res) => assert_eq!(res.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE),
        Err(e) => {
            // The server typically aborts the connection (RequestBodyLimitLayer).
            // Any error here indicates the server refused to process the 22MB bomb.
            println!("Confirmed: Server rejected 22MB bomb: {}", e);
        }
    }
}

#[tokio::test]
async fn test_aggressive_queue_flood_stress() {
    let secret = "test_queue_secret";
    let addr = spawn_test_server(secret).await;
    let client = Client::new();
    let url = format!("http://{}/v1/messages/send", addr);

    // Create proper Ed25519 identities for Alice and Bob
    let ctx_alice = SecureContext::new(Config::default(), None).unwrap();
    ctx_alice.generate_identity().unwrap();
    let alice_id = ctx_alice.get_identity().unwrap().ed25519_public;
    let alice_id_hex = hex::encode(alice_id);
    let alice_token = create_mock_jwt(&alice_id_hex, secret);

    // Bob's identity for recipient
    let ctx_bob = SecureContext::new(Config::default(), None).unwrap();
    ctx_bob.generate_identity().unwrap();
    let bob_id = ctx_bob.get_identity().unwrap().ed25519_public;
    let bob_id_hex = hex::encode(bob_id);

    // ATTACK: Flood a single recipient with 500 messages (Offline Queue stress)
    for i in 0..500 {
        let req = json!({
            "recipient_id": bob_id_hex,
            "payload_hex": "aabbcc".repeat(100),
            "message_id": format!("msg_{}", i)
        });

        let res = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", alice_token))
            .json(&req)
            .send()
            .await
            .unwrap();

        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        assert!(
            status.is_success() || status == reqwest::StatusCode::TOO_MANY_REQUESTS,
            "Unexpected status {}: {}",
            status,
            body
        );

        // Small delay between requests to avoid overwhelming the server under
        // concurrent test load (multiple server instances running simultaneously
        // on the same machine). This keeps the test deterministic on Windows
        // without weakening the flood-stress assertions.
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

#[tokio::test]
async fn test_aggressive_prekey_race_condition() {
    let secret = "test_race_secret";
    let addr = spawn_test_server(secret).await;
    let client = Client::new();
    let url_upload = format!("http://{}/v1/prekeys/upload", addr);
    let url_fetch = format!("http://{}/v1/prekeys/alice", addr);

    let alice_token = create_mock_jwt("alice", secret);

    let mut handlers = Vec::new();
    for i in 0..50 {
        let client_clone = client.clone();
        let token_clone = alice_token.clone();
        let upload_url = url_upload.clone();
        let fetch_url = url_fetch.clone();

        handlers.push(tokio::spawn(async move {
            if i % 2 == 0 {
                let bundle = hex::encode(vec![0u8; 100]);
                client_clone
                    .post(&upload_url)
                    .header("Authorization", format!("Bearer {}", token_clone))
                    .json(&json!({"bundle_hex": bundle}))
                    .send()
                    .await
                    .ok();
            } else {
                client_clone.get(&fetch_url).send().await.ok();
            }
        }));
    }

    for h in handlers {
        h.await.ok();
    }
    let resp = client
        .get(format!("http://{}/health", addr))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    assert!(status.is_success());
}

#[tokio::test]
async fn test_delayed_queue_delivery_and_ack() {
    // Regression test for delayed (offline-queued) message delivery:
    // a message queued while the recipient is offline must be delivered when
    // the recipient reconnects, and an explicit ACK must remove it from the
    // queue so it is not redelivered after a reconnect.
    let secret = "test_delayed_queue_secret";
    let addr = spawn_test_server(secret).await;
    let client = Client::new();
    let url = format!("http://{}/v1/messages/send", addr);

    // Create proper Ed25519 identities for Alice and Bob
    let ctx_alice = SecureContext::new(Config::default(), None).unwrap();
    ctx_alice.generate_identity().unwrap();
    let alice_id = ctx_alice.get_identity().unwrap().ed25519_public;
    let alice_id_hex = hex::encode(alice_id);
    let alice_token = create_mock_jwt(&alice_id_hex, secret);

    let ctx_bob = SecureContext::new(Config::default(), None).unwrap();
    ctx_bob.generate_identity().unwrap();
    let bob_id = ctx_bob.get_identity().unwrap().ed25519_public;
    let bob_id_hex = hex::encode(bob_id);
    let bob_token = create_mock_jwt(&bob_id_hex, secret);

    // Alice sends to Bob while Bob is offline: message is queued (202).
    // recipient_id must be the 64-char hex-encoded Ed25519 public key.
    let req = json!({
        "recipient_id": bob_id_hex,
        "payload_hex": "deadbeef",
        "compressed": false,
    });
    let res = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", alice_token))
        .json(&req)
        .send()
        .await
        .unwrap();
    assert!(
        res.status().is_success() || res.status() == reqwest::StatusCode::ACCEPTED,
        "queued message must be accepted: {}",
        res.status()
    );

    // Bob connects and receives the queued (delayed) message.
    let ws_url = format!("ws://{}/ws?token={}", addr, bob_token);
    let (mut ws, _) = connect_async(&ws_url).await.expect("Bob WS connect");

    let mut received = None;
    for _ in 0..40 {
        if let Some(Ok(msg)) = ws.next().await {
            let text = match &msg {
                Message::Text(t) => t.clone(),
                Message::Binary(b) => String::from_utf8_lossy(b).into_owned(),
                _ => continue,
            };
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                if v.get("type").and_then(|t| t.as_str()) == Some("envelope") {
                    received = Some(v);
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let envelope = received.expect("Bob should receive the queued delayed message");
    assert_eq!(envelope["recipient_id"], bob_id_hex);

    // Bob ACKs the message so it is removed from the queue.
    let message_id = envelope["message_id"].as_str().unwrap();
    ws.send(Message::Text(
        serde_json::to_string(&serde_json::json!({ "type": "ack", "message_id": message_id }))
            .unwrap(),
    ))
    .await
    .unwrap();

    // Bob reconnects: the ACKed message must NOT be redelivered.
    drop(ws);
    let (mut ws2, _) = connect_async(&ws_url).await.expect("Bob WS reconnect");
    let mut redelivered = false;
    for _ in 0..20 {
        if let Some(Ok(msg)) = ws2.next().await {
            let text = match &msg {
                Message::Text(t) => t.clone(),
                Message::Binary(b) => String::from_utf8_lossy(b).into_owned(),
                _ => continue,
            };
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                if v.get("type").and_then(|t| t.as_str()) == Some("envelope") {
                    redelivered = true;
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        !redelivered,
        "ACKed message must not be redelivered on reconnect"
    );
}

#[tokio::test]
async fn test_health_endpoint_version() {
    let secret = "test_health_secret";
    let addr = spawn_test_server(secret).await;
    let client = Client::new();

    let resp = client
        .get(format!("http://{}/health", addr))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["version"], "3.0.2");
    assert_eq!(body["status"], "ok");
}
