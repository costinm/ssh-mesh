use futures_util::StreamExt;
use reqwest::StatusCode;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message as WsMessage};
use ws::{ClientsResponse, SendMessageRequest, WSServer};

async fn spawn_app() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = Arc::new(WSServer::new());

    let app = axum::Router::new()
        .route("/", axum::routing::get(root_handler))
        .route("/ws", axum::routing::get(ws::handle_websocket_upgrade))
        .route("/api/clients", axum::routing::get(ws::handle_list_clients))
        .route(
            "/api/clients/:id",
            axum::routing::delete(ws::handle_remove_client),
        )
        .route(
            "/api/clients/:id/message",
            axum::routing::post(ws::handle_send_message),
        )
        .route("/api/broadcast", axum::routing::post(ws::handle_broadcast))
        .with_state(server);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    format!("ws://{}", addr)
}

async fn root_handler() -> impl axum::response::IntoResponse {
    "Hello from test server"
}

#[tokio::test]
async fn test_websocket_operations() {
    let base_addr = spawn_app().await;
    let http_base_addr = base_addr.replace("ws://", "http://");

    // Connect client 1
    let (mut client1, _) = connect_async(format!("{}/ws", base_addr)).await.unwrap();
    // Connect client 2
    let (mut client2, _) = connect_async(format!("{}/ws", base_addr)).await.unwrap();

    // Give some time for connections to be registered
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let http_client = reqwest::Client::new();

    // 1. List clients
    let response = http_client
        .get(format!("{}/api/clients", http_base_addr))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let clients_response: ClientsResponse = response.json().await.unwrap();
    assert_eq!(clients_response.clients.len(), 2);
    let client1_id = clients_response
        .clients
        .iter()
        .find(|id| id.starts_with("client_"))
        .cloned()
        .unwrap();
    let client2_id = clients_response
        .clients
        .iter()
        .find(|id| *id != &client1_id)
        .cloned()
        .unwrap();

    // 2. Send to client 1
    let message_to_client1 = "Hello client 1";
    let payload = SendMessageRequest {
        message: message_to_client1.to_string(),
    };
    let response = http_client
        .post(format!(
            "{}/api/clients/{}/message",
            http_base_addr, client1_id
        ))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Verify client 1 received the message
    let msg1 = client1.next().await.unwrap().unwrap();
    assert_eq!(msg1, WsMessage::Text(message_to_client1.to_string()));

    // 3. Broadcast
    let broadcast_message = "Hello everyone";
    let payload = SendMessageRequest {
        message: broadcast_message.to_string(),
    };
    let response = http_client
        .post(format!("{}/api/broadcast", http_base_addr))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Verify both clients received the broadcast
    let msg_b1 = client1.next().await.unwrap().unwrap();
    assert_eq!(msg_b1, WsMessage::Text(broadcast_message.to_string()));
    let msg_b2 = client2.next().await.unwrap().unwrap();
    assert_eq!(msg_b2, WsMessage::Text(broadcast_message.to_string()));

    // 4. Remove client 2
    let response = http_client
        .delete(format!("{}/api/clients/{}", http_base_addr, client2_id))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Give some time for removal
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // 5. List clients again
    let response = http_client
        .get(format!("{}/api/clients", http_base_addr))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let clients_response: ClientsResponse = response.json().await.unwrap();
    assert_eq!(clients_response.clients.len(), 1);
    assert_eq!(clients_response.clients[0], client1_id);

    // 6. Close connection from client 1
    client1.close(None).await.unwrap();
    // Give some time for the server to detect disconnection
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // 7. List clients for the last time
    let response = http_client
        .get(format!("{}/api/clients", http_base_addr))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let clients_response: ClientsResponse = response.json().await.unwrap();
    assert_eq!(clients_response.clients.len(), 0);
}