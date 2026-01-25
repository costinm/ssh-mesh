use anyhow::Result;
use serde_json::Value;
use std::process::Command;
use std::time::Duration;
use ssh_mesh::test_utils::setup_test_environment;
use tokio::time::timeout;

async fn run_test_with_timeout<F, Fut>(test_fn: F) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    timeout(Duration::from_secs(20), test_fn()).await?
}

#[tokio::test]
async fn test_client_api() -> Result<()> {
    run_test_with_timeout(|| async {
        let setup = setup_test_environment(None, true).await?;
        let http_port = setup.http_port.unwrap();
        
        let client = reqwest::Client::new();

        // 1. Initially, no clients should be connected
        let res: Value = client
            .get(format!(
                "http://127.0.0.1:{}/api/ssh/clients",
                http_port
            ))
            .send()
            .await?
            .json()
            .await?;
        assert!(res.as_object().unwrap().is_empty());

        // 2. Connect an SSH client
        let mut ssh_client_process = Command::new("ssh")
            .arg("-v") // Enable verbose logging for client debugging
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg("-o")
            .arg("UserKnownHostsFile=/dev/null")
            .arg("-o")
            .arg("ControlMaster=no")
            .arg("-o")
            .arg("ControlPath=none")
            .arg("-i")
            .arg(setup.client_key_path.to_str().unwrap())
            .arg("-p")
            .arg(setup.ssh_port.to_string())
            .arg("-l")
            .arg("testuser")
            .arg("127.0.0.1")
            .arg("-N") // Do not execute a remote command, just connect.
            .spawn()?;

        // Give it time to connect and authenticate
        tokio::time::sleep(Duration::from_secs(2)).await;

        // 3. Verify the client is listed in the API
        let res: Value = client
            .get(format!(
                "http://127.0.0.1:{}/api/ssh/clients",
                http_port
            ))
            .send()
            .await?
            .json()
            .await?;

        let clients = res.as_object().unwrap();
        assert_eq!(clients.len(), 1); // Should have 1 client now
        let client_info = clients.values().next().unwrap();
        assert_eq!(client_info["user"], "testuser");

        // 4. Disconnect the client
        ssh_client_process.kill()?;
        ssh_client_process.wait()?;

        // Give the server a moment to recognize the disconnect
        tokio::time::sleep(Duration::from_secs(10)).await;

        // 5. Verify the client is no longer listed
        let res: Value = client
            .get(format!(
                "http://127.0.0.1:{}/api/ssh/clients",
                http_port
            ))
            .send()
            .await?
            .json()
            .await?;
        assert!(res.as_object().unwrap().is_empty());

        setup.server_handle.abort();
        Ok(())
    })
    .await
}

#[tokio::test]
async fn test_client_api_over_http2() -> Result<()> {
    run_test_with_timeout(|| async {
        let setup = setup_test_environment(None, true).await?;
        let http_port = setup.http_port.unwrap();
        let client = reqwest::Client::new();

        // 1. Initially, no clients should be connected
        let res: Value = client
            .get(format!(
                "http://127.0.0.1:{}/api/ssh/clients",
                http_port
            ))
            .send()
            .await?
            .json()
            .await?;
        assert!(res.as_object().unwrap().is_empty());

        // 2. Connect an SSH client via HTTP/2 proxy (H2C)

        // Use the h2t binary built by cargo

        let h2t_binary = env!("CARGO_BIN_EXE_h2t");

        let proxy_command = format!("{} http://127.0.0.1:{}/_ssh", h2t_binary, http_port);

        let mut ssh_client_process = Command::new("ssh")
            .arg("-v")
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg("-o")
            .arg("UserKnownHostsFile=/dev/null")
            .arg("-o")
            .arg("ControlMaster=no")
            .arg("-o")
            .arg("ControlPath=none")
            .arg("-o")
            .arg(format!("ProxyCommand={}", proxy_command))
            .arg("-i")
            .arg(setup.client_key_path.to_str().unwrap())
            .arg("-l")
            .arg("testuser")
            .arg("127.0.0.1")
            .arg("-N")
            .spawn()?;

        // Give it time to connect and authenticate
        tokio::time::sleep(Duration::from_secs(5)).await;

        // 3. Verify the client is listed in the API
        let res: Value = client
            .get(format!(
                "http://127.0.0.1:{}/api/ssh/clients",
                http_port
            ))
            .send()
            .await?
            .json()
            .await?;

        let clients = res.as_object().unwrap();
        assert_eq!(
            clients.len(),
            1,
            "Should have 1 client connected over HTTP/2"
        );
        let client_info = clients.values().next().unwrap();
        assert_eq!(client_info["user"], "testuser");

        // 4. Disconnect the client
        ssh_client_process.kill()?;
        ssh_client_process.wait()?;

        // Give the server a moment to recognize the disconnect
        tokio::time::sleep(Duration::from_secs(5)).await;

        // 5. Verify the client is no longer listed
        let res: Value = client
            .get(format!(
                "http://127.0.0.1:{}/api/ssh/clients",
                http_port
            ))
            .send()
            .await?
            .json()
            .await?;
        assert!(
            res.as_object().unwrap().is_empty(),
            "Client list should be empty after disconnect"
        );

        setup.server_handle.abort();
        Ok(())
    })
    .await
}
