use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

use multiplayer_server::{
    AppState, Result, api, build_router, db, wireguard,
};

// ---------------------------------------------------------------------------
// Mock WireGuard operations (no-op, returns canned values)
// ---------------------------------------------------------------------------

struct MockWgOps;

impl wireguard::WgOps for MockWgOps {
    fn generate_keypair(&self) -> Result<(String, String)> {
        Ok((
            "mock-server-private-key".to_string(),
            "mock-server-public-key".to_string(),
        ))
    }
    fn write_server_config(
        &self,
        _interface_name: &str,
        _private_key: &str,
        _address: &str,
        _listen_port: u16,
    ) -> Result<String> {
        Ok("/tmp/mock-wg.conf".to_string())
    }
    fn interface_up(&self, _interface_name: &str) -> Result<()> {
        Ok(())
    }
    fn interface_down(&self, _interface_name: &str) -> Result<()> {
        Ok(())
    }
    fn add_peer(
        &self,
        _interface_name: &str,
        _public_key: &str,
        _allowed_ips: &str,
    ) -> Result<()> {
        Ok(())
    }
    fn remove_config(&self, _interface_name: &str) {}
    fn get_interface_public_key(&self, _interface_name: &str) -> Option<String> {
        Some("mock-server-public-key".to_string())
    }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn test_state(register_secret: Option<&str>) -> Arc<AppState> {
    Arc::new(AppState {
        db: db::Db::open_in_memory().expect("in-memory DB"),
        server_url: "http://localhost:8080".to_string(),
        wg_endpoint: "127.0.0.1".to_string(),
        wg_port_start: 51820,
        rate_limiter: api::RateLimiter::new(10),
        register_secret: register_secret.map(|s| s.to_string()),
        wg: Box::new(MockWgOps),
    })
}

async fn body_json(body: Body) -> Value {
    let bytes = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn post_json(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}

fn post_json_auth(uri: &str, body: Value, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}

fn delete_auth(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

/// Register a user and return the token.
async fn register_user(state: &Arc<AppState>, username: &str, secret: &str) -> String {
    let app = build_router(Arc::clone(state));
    let resp = app
        .oneshot(post_json(
            "/api/register",
            json!({ "username": username, "secret": secret }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "register failed");
    let body = body_json(resp.into_body()).await;
    body["token"].as_str().unwrap().to_string()
}

/// Create a session and return (session_id, join_url, join_token).
async fn create_test_session(
    state: &Arc<AppState>,
    token: &str,
    name: &str,
) -> (String, String) {
    let app = build_router(Arc::clone(state));
    let resp = app
        .oneshot(post_json_auth(
            "/api/sessions",
            json!({
                "session_name": name,
                "host_wg_public_key": "host-wg-pubkey",
                "ssh_user": "testuser",
                "ssh_private_key_b64": "c3NoLXByaXZhdGUta2V5",
            }),
            token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "create_session failed");
    let body = body_json(resp.into_body()).await;
    let session_id = body["session_id"].as_str().unwrap().to_string();
    let join_url = body["join_url"].as_str().unwrap().to_string();
    (session_id, join_url)
}

/// Extract the join token from a join URL like http://localhost:8080/s/{id}/{token}
fn extract_join_token(join_url: &str) -> String {
    join_url.rsplit('/').next().unwrap().to_string()
}

// ===========================================================================
// Registration tests
// ===========================================================================

#[tokio::test]
async fn register_success() {
    let state = test_state(Some("test-secret"));
    let token = register_user(&state, "alice", "test-secret").await;
    assert!(!token.is_empty());
}

#[tokio::test]
async fn register_wrong_secret() {
    let state = test_state(Some("test-secret"));
    let app = build_router(Arc::clone(&state));

    let resp = app
        .oneshot(post_json(
            "/api/register",
            json!({ "username": "alice", "secret": "wrong" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn register_no_secret_configured() {
    let state = test_state(None);
    let app = build_router(Arc::clone(&state));

    let resp = app
        .oneshot(post_json(
            "/api/register",
            json!({ "username": "alice", "secret": "anything" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn register_missing_secret_field() {
    let state = test_state(Some("test-secret"));
    let app = build_router(Arc::clone(&state));

    let resp = app
        .oneshot(post_json(
            "/api/register",
            json!({ "username": "alice" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn register_duplicate_username() {
    let state = test_state(Some("test-secret"));
    register_user(&state, "alice", "test-secret").await;

    let app = build_router(Arc::clone(&state));
    let resp = app
        .oneshot(post_json(
            "/api/register",
            json!({ "username": "alice", "secret": "test-secret" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn register_empty_username() {
    let state = test_state(Some("test-secret"));
    let app = build_router(Arc::clone(&state));

    let resp = app
        .oneshot(post_json(
            "/api/register",
            json!({ "username": "", "secret": "test-secret" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn register_username_too_long() {
    let state = test_state(Some("test-secret"));
    let app = build_router(Arc::clone(&state));

    let long_name = "a".repeat(65);
    let resp = app
        .oneshot(post_json(
            "/api/register",
            json!({ "username": long_name, "secret": "test-secret" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn register_invalid_username_chars() {
    let state = test_state(Some("test-secret"));
    let app = build_router(Arc::clone(&state));

    let resp = app
        .oneshot(post_json(
            "/api/register",
            json!({ "username": "alice bob", "secret": "test-secret" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn register_valid_special_chars() {
    let state = test_state(Some("test-secret"));
    let token = register_user(&state, "alice-bob_123", "test-secret").await;
    assert!(!token.is_empty());
}

// ===========================================================================
// Authentication tests
// ===========================================================================

#[tokio::test]
async fn create_session_no_auth() {
    let state = test_state(Some("test-secret"));
    let app = build_router(Arc::clone(&state));

    let resp = app
        .oneshot(post_json(
            "/api/sessions",
            json!({
                "session_name": "test",
                "host_wg_public_key": "key",
                "ssh_user": "user",
                "ssh_private_key_b64": "key",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn create_session_bad_token() {
    let state = test_state(Some("test-secret"));
    let app = build_router(Arc::clone(&state));

    let resp = app
        .oneshot(post_json_auth(
            "/api/sessions",
            json!({
                "session_name": "test",
                "host_wg_public_key": "key",
                "ssh_user": "user",
                "ssh_private_key_b64": "key",
            }),
            "invalid-token",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ===========================================================================
// Create session tests
// ===========================================================================

#[tokio::test]
async fn create_session_success() {
    let state = test_state(Some("s"));
    let token = register_user(&state, "alice", "s").await;
    let (session_id, join_url) = create_test_session(&state, &token, "my-session").await;

    assert!(!session_id.is_empty());
    assert!(join_url.contains(&session_id));
    assert!(join_url.starts_with("http://localhost:8080/s/"));
}

#[tokio::test]
async fn create_session_response_contains_wg_config() {
    let state = test_state(Some("s"));
    let token = register_user(&state, "alice", "s").await;
    let app = build_router(Arc::clone(&state));

    let resp = app
        .oneshot(post_json_auth(
            "/api/sessions",
            json!({
                "session_name": "test",
                "host_wg_public_key": "host-key",
                "ssh_user": "user",
                "ssh_private_key_b64": "key",
            }),
            &token,
        ))
        .await
        .unwrap();
    let body = body_json(resp.into_body()).await;

    let wg = &body["wg_config"];
    assert_eq!(wg["host_address"], "10.100.1.1/24");
    assert_eq!(wg["server_public_key"], "mock-server-public-key");
    assert!(wg["server_endpoint"].as_str().unwrap().starts_with("127.0.0.1:"));
    assert_eq!(wg["allowed_ips"], "10.100.1.0/24");
}

#[tokio::test]
async fn create_session_limit() {
    let state = test_state(Some("s"));
    let token = register_user(&state, "alice", "s").await;

    // Create 5 sessions (the limit)
    for i in 0..5 {
        create_test_session(&state, &token, &format!("sess-{i}")).await;
    }

    // 6th should fail
    let app = build_router(Arc::clone(&state));
    let resp = app
        .oneshot(post_json_auth(
            "/api/sessions",
            json!({
                "session_name": "too-many",
                "host_wg_public_key": "key",
                "ssh_user": "user",
                "ssh_private_key_b64": "key",
            }),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn create_session_subnet_increments() {
    let state = test_state(Some("s"));
    let token = register_user(&state, "alice", "s").await;

    // Create two sessions and verify different subnets
    let app = build_router(Arc::clone(&state));
    let resp = app
        .oneshot(post_json_auth(
            "/api/sessions",
            json!({
                "session_name": "first",
                "host_wg_public_key": "key1",
                "ssh_user": "user",
                "ssh_private_key_b64": "key",
            }),
            &token,
        ))
        .await
        .unwrap();
    let body1 = body_json(resp.into_body()).await;

    let app = build_router(Arc::clone(&state));
    let resp = app
        .oneshot(post_json_auth(
            "/api/sessions",
            json!({
                "session_name": "second",
                "host_wg_public_key": "key2",
                "ssh_user": "user",
                "ssh_private_key_b64": "key",
            }),
            &token,
        ))
        .await
        .unwrap();
    let body2 = body_json(resp.into_body()).await;

    assert_eq!(body1["wg_config"]["host_address"], "10.100.1.1/24");
    assert_eq!(body2["wg_config"]["host_address"], "10.100.2.1/24");
}

// ===========================================================================
// Join session tests
// ===========================================================================

#[tokio::test]
async fn join_session_success() {
    let state = test_state(Some("s"));
    let token = register_user(&state, "alice", "s").await;
    let (session_id, join_url) = create_test_session(&state, &token, "my-session").await;
    let join_token = extract_join_token(&join_url);

    let app = build_router(Arc::clone(&state));
    let resp = app
        .oneshot(post_json(
            &format!("/api/sessions/{session_id}/join"),
            json!({
                "token": join_token,
                "guest_wg_public_key": "guest-wg-pubkey",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_json(resp.into_body()).await;
    let wg = &body["wg_config"];
    assert_eq!(wg["guest_address"], "10.100.1.2/24");
    assert_eq!(wg["server_public_key"], "mock-server-public-key");

    let ssh_token = body["ssh_token"].as_str().unwrap();
    assert!(ssh_token.starts_with("mp://testuser@10.100.1.1:22/my-session#"));
}

#[tokio::test]
async fn join_session_wrong_token() {
    let state = test_state(Some("s"));
    let token = register_user(&state, "alice", "s").await;
    let (session_id, _) = create_test_session(&state, &token, "test").await;

    let app = build_router(Arc::clone(&state));
    let resp = app
        .oneshot(post_json(
            &format!("/api/sessions/{session_id}/join"),
            json!({
                "token": "wrong-token",
                "guest_wg_public_key": "key",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn join_session_not_found() {
    let state = test_state(Some("s"));
    let app = build_router(Arc::clone(&state));

    let resp = app
        .oneshot(post_json(
            "/api/sessions/nonexistent/join",
            json!({
                "token": "whatever",
                "guest_wg_public_key": "key",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn join_session_multiple_guests_get_different_ips() {
    let state = test_state(Some("s"));
    let token = register_user(&state, "alice", "s").await;
    let (session_id, join_url) = create_test_session(&state, &token, "shared").await;
    let join_token = extract_join_token(&join_url);

    // Guest 1
    let app = build_router(Arc::clone(&state));
    let resp = app
        .oneshot(post_json(
            &format!("/api/sessions/{session_id}/join"),
            json!({ "token": &join_token, "guest_wg_public_key": "guest1-key" }),
        ))
        .await
        .unwrap();
    let body1 = body_json(resp.into_body()).await;

    // Guest 2
    let app = build_router(Arc::clone(&state));
    let resp = app
        .oneshot(post_json(
            &format!("/api/sessions/{session_id}/join"),
            json!({ "token": &join_token, "guest_wg_public_key": "guest2-key" }),
        ))
        .await
        .unwrap();
    let body2 = body_json(resp.into_body()).await;

    assert_eq!(body1["wg_config"]["guest_address"], "10.100.1.2/24");
    assert_eq!(body2["wg_config"]["guest_address"], "10.100.1.3/24");
}

#[tokio::test]
async fn join_session_rate_limited() {
    // Rate limiter allows 2 per minute for this test
    let state = Arc::new(AppState {
        db: db::Db::open_in_memory().expect("in-memory DB"),
        server_url: "http://localhost:8080".to_string(),
        wg_endpoint: "127.0.0.1".to_string(),
        wg_port_start: 51820,
        rate_limiter: api::RateLimiter::new(2),
        register_secret: Some("s".to_string()),
        wg: Box::new(MockWgOps),
    });

    let token = register_user(&state, "alice", "s").await;
    let (session_id, join_url) = create_test_session(&state, &token, "test").await;
    let join_token = extract_join_token(&join_url);

    // First 2 should succeed
    for i in 0..2 {
        let app = build_router(Arc::clone(&state));
        let resp = app
            .oneshot(post_json(
                &format!("/api/sessions/{session_id}/join"),
                json!({ "token": &join_token, "guest_wg_public_key": format!("key-{i}") }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "request {i} should succeed");
    }

    // 3rd should be rate limited
    let app = build_router(Arc::clone(&state));
    let resp = app
        .oneshot(post_json(
            &format!("/api/sessions/{session_id}/join"),
            json!({ "token": &join_token, "guest_wg_public_key": "key-extra" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

// ===========================================================================
// Heartbeat tests
// ===========================================================================

#[tokio::test]
async fn heartbeat_success() {
    let state = test_state(Some("s"));
    let token = register_user(&state, "alice", "s").await;
    let (session_id, _) = create_test_session(&state, &token, "test").await;

    let app = build_router(Arc::clone(&state));
    let resp = app
        .oneshot(post_json_auth(
            &format!("/api/sessions/{session_id}/heartbeat"),
            json!({}),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn heartbeat_not_found() {
    let state = test_state(Some("s"));
    let token = register_user(&state, "alice", "s").await;

    let app = build_router(Arc::clone(&state));
    let resp = app
        .oneshot(post_json_auth(
            "/api/sessions/nonexistent/heartbeat",
            json!({}),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn heartbeat_requires_auth() {
    let state = test_state(Some("s"));
    let app = build_router(Arc::clone(&state));

    let resp = app
        .oneshot(post_json(
            "/api/sessions/whatever/heartbeat",
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ===========================================================================
// Delete session tests
// ===========================================================================

#[tokio::test]
async fn delete_session_success() {
    let state = test_state(Some("s"));
    let token = register_user(&state, "alice", "s").await;
    let (session_id, _) = create_test_session(&state, &token, "test").await;

    let app = build_router(Arc::clone(&state));
    let resp = app
        .oneshot(delete_auth(
            &format!("/api/sessions/{session_id}"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Verify session is gone
    let session = state.db.find_session_by_session_id(&session_id).unwrap();
    assert!(session.is_none());
}

#[tokio::test]
async fn delete_session_not_found() {
    let state = test_state(Some("s"));
    let token = register_user(&state, "alice", "s").await;

    let app = build_router(Arc::clone(&state));
    let resp = app
        .oneshot(delete_auth("/api/sessions/nonexistent", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_session_wrong_user() {
    let state = test_state(Some("s"));
    let alice_token = register_user(&state, "alice", "s").await;
    let bob_token = register_user(&state, "bob", "s").await;
    let (session_id, _) = create_test_session(&state, &alice_token, "alice-session").await;

    // Bob tries to delete Alice's session
    let app = build_router(Arc::clone(&state));
    let resp = app
        .oneshot(delete_auth(
            &format!("/api/sessions/{session_id}"),
            &bob_token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Verify session still exists
    let session = state.db.find_session_by_session_id(&session_id).unwrap();
    assert!(session.is_some());
}

#[tokio::test]
async fn delete_session_requires_auth() {
    let state = test_state(Some("s"));
    let app = build_router(Arc::clone(&state));

    let resp = app
        .oneshot(delete_auth("/api/sessions/whatever", "bad-token"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn delete_session_cascades_peers() {
    let state = test_state(Some("s"));
    let token = register_user(&state, "alice", "s").await;
    let (session_id, join_url) = create_test_session(&state, &token, "test").await;
    let join_token = extract_join_token(&join_url);

    // Add a guest peer
    let app = build_router(Arc::clone(&state));
    app.oneshot(post_json(
        &format!("/api/sessions/{session_id}/join"),
        json!({ "token": &join_token, "guest_wg_public_key": "guest-key" }),
    ))
    .await
    .unwrap();

    // Verify peer exists
    let session = state.db.find_session_by_session_id(&session_id).unwrap().unwrap();
    let peers = state.db.peers_for_session(session.id).unwrap();
    assert_eq!(peers.len(), 1);

    // Delete session
    let app = build_router(Arc::clone(&state));
    let resp = app
        .oneshot(delete_auth(
            &format!("/api/sessions/{session_id}"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Peers should be cascade-deleted (session gone, so we check via DB directly)
    let session = state.db.find_session_by_session_id(&session_id).unwrap();
    assert!(session.is_none());
}

// ===========================================================================
// Database-level tests
// ===========================================================================

#[test]
fn db_create_and_find_user() {
    let db = db::Db::open_in_memory().unwrap();
    let id = db.create_user("alice", "hash123").unwrap();
    assert!(id > 0);

    let user = db.find_user_by_token_hash("hash123").unwrap().unwrap();
    assert_eq!(user.username, "alice");
    assert_eq!(user.token_hash, "hash123");
}

#[test]
fn db_username_exists() {
    let db = db::Db::open_in_memory().unwrap();
    assert!(!db.username_exists("alice").unwrap());
    db.create_user("alice", "hash").unwrap();
    assert!(db.username_exists("alice").unwrap());
}

#[test]
fn db_duplicate_username_fails() {
    let db = db::Db::open_in_memory().unwrap();
    db.create_user("alice", "hash1").unwrap();
    assert!(db.create_user("alice", "hash2").is_err());
}

#[test]
fn db_subnet_index_increments() {
    let db = db::Db::open_in_memory().unwrap();

    // First subnet should be 1
    assert_eq!(db.next_subnet_index().unwrap(), 1);

    // Create a user and session
    let user_id = db.create_user("alice", "hash").unwrap();
    db.create_session(
        "sess-1", user_id, "test", "token-hash", "wg-key",
        "user", "ssh-key", "wg-mp-1", 1, "10.100.1.1/24",
    )
    .unwrap();

    // Next should be 2
    assert_eq!(db.next_subnet_index().unwrap(), 2);

    db.create_session(
        "sess-2", user_id, "test2", "token-hash2", "wg-key2",
        "user", "ssh-key", "wg-mp-2", 2, "10.100.2.1/24",
    )
    .unwrap();

    assert_eq!(db.next_subnet_index().unwrap(), 3);
}

#[test]
fn db_peer_index_starts_at_2() {
    let db = db::Db::open_in_memory().unwrap();
    let user_id = db.create_user("alice", "hash").unwrap();
    let session_id = db
        .create_session(
            "sess-1", user_id, "test", "token-hash", "wg-key",
            "user", "ssh-key", "wg-mp-1", 1, "10.100.1.1/24",
        )
        .unwrap();

    // First peer index should be 2 (host=1, server=254)
    assert_eq!(db.next_peer_index(session_id).unwrap(), 2);

    db.add_peer(session_id, "peer-key-1", "10.100.1.2/24", 2).unwrap();
    assert_eq!(db.next_peer_index(session_id).unwrap(), 3);
}

#[test]
fn db_user_active_session_count() {
    let db = db::Db::open_in_memory().unwrap();
    let user_id = db.create_user("alice", "hash").unwrap();

    assert_eq!(db.user_active_session_count(user_id).unwrap(), 0);

    db.create_session(
        "sess-1", user_id, "test", "token", "wg", "user", "ssh", "wg-1", 1, "addr",
    )
    .unwrap();
    assert_eq!(db.user_active_session_count(user_id).unwrap(), 1);

    db.create_session(
        "sess-2", user_id, "test2", "token2", "wg2", "user", "ssh", "wg-2", 2, "addr",
    )
    .unwrap();
    assert_eq!(db.user_active_session_count(user_id).unwrap(), 2);

    db.delete_session("sess-1").unwrap();
    assert_eq!(db.user_active_session_count(user_id).unwrap(), 1);
}

#[test]
fn db_delete_session_returns_false_for_nonexistent() {
    let db = db::Db::open_in_memory().unwrap();
    assert!(!db.delete_session("nonexistent").unwrap());
}

#[test]
fn db_heartbeat_update() {
    let db = db::Db::open_in_memory().unwrap();
    let user_id = db.create_user("alice", "hash").unwrap();
    db.create_session(
        "sess-1", user_id, "test", "token", "wg", "user", "ssh", "wg-1", 1, "addr",
    )
    .unwrap();

    assert!(db.update_heartbeat("sess-1").unwrap());
    assert!(!db.update_heartbeat("nonexistent").unwrap());
}

// ===========================================================================
// Auth helper tests
// ===========================================================================

#[test]
fn sha256_hex_deterministic() {
    use multiplayer_server::auth::sha256_hex;

    let hash1 = sha256_hex("hello");
    let hash2 = sha256_hex("hello");
    assert_eq!(hash1, hash2);

    let hash3 = sha256_hex("world");
    assert_ne!(hash1, hash3);

    // Known value check
    assert_eq!(
        sha256_hex("test"),
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    );
}
