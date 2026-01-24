use anyhow::Result;
use ssh_mesh::test_utils::setup_test_environment;
use tokio::process::Command;
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn test_sftp_basic_ops() -> Result<()> {
    timeout(Duration::from_secs(60), async {
        let setup = setup_test_environment(None, false).await?;

        // Create a test file in the base directory
        let test_file_path = setup.base_dir.join("hello.txt");
        std::fs::write(&test_file_path, "Hello from SFTP test!")?;

        // Run sftp batch command to list files and get the test file
        let batch_file = setup.base_dir.join("sftp_batch");
        std::fs::write(&batch_file, "ls\nget hello.txt hello_got.txt\n")?;
        println!("TEST: Batch file created at {:?}", batch_file);

        // 2. SFTP test
        let mut child = Command::new("sftp")
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg("-o")
            .arg("UserKnownHostsFile=/dev/null")
            .arg("-o")
            .arg("ConnectTimeout=10")
            .arg("-i")
            .arg(setup.client_key_path.to_str().unwrap())
            .arg("-P")
            .arg(setup.ssh_port.to_string())
            .arg("-b")
            .arg(batch_file.to_str().unwrap())
            .arg("testuser@127.0.0.1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        
        let wait_result = timeout(Duration::from_secs(30), child.wait()).await;
        let status = wait_result.expect("SFTP command timed out")?;
        assert!(status.success(), "SFTP command failed with status: {:?}", status);

        // Verify the file was downloaded
        let downloaded_file = std::path::Path::new("hello_got.txt");
        assert!(downloaded_file.exists(), "Downloaded file not found");
        let content = std::fs::read_to_string(downloaded_file)?;
        assert_eq!(content, "Hello from SFTP test!");
        let _ = std::fs::remove_file(downloaded_file);

        setup.server_handle.abort();
        Ok(())
    }).await?
}
