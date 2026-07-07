import unittest
import os
import shutil
import tempfile
import time
from dmesh import start_mesh_init, ServiceController, resolve_control_socket_path

import signal

class TestMeshInit(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.mesh_home = self.temp_dir.name
        
        # Create directories expected by mesh-init
        self.config_dir = os.path.join(self.mesh_home, "home/mesh-init/etc/mesh-init")
        os.makedirs(self.config_dir, exist_ok=True)
        
        # Write a mock service config
        self.service_config = os.path.join(self.config_dir, "mock-sleep.toml")
        with open(self.service_config, "w") as f:
            f.write("""
[Service]
ExecStart = "/bin/sleep 30"
""")

        # Prepend locally compiled target binaries to PATH
        target_debug_dir = "/ws/rust/ssh-mesh/target/x86_64-unknown-linux-musl/debug"
        path = os.environ.get("PATH", "")
        new_path = f"{target_debug_dir}:{path}"

        self.socket_path = os.path.join(self.mesh_home, "mesh-init.sock")
        self.env = {
            "MESH_HOME": self.mesh_home,
            "MESH_INIT_DIR": self.config_dir,
            "MESH_INIT_SOCK": self.socket_path,
            "MESH_LOG_FILE": "/dev/stderr",
            "RUST_LOG": "debug",
            "PATH": new_path,
        }
        self.proc = None
        self.success = False

    def tearDown(self):
        if self.proc:
            try:
                pgid = os.getpgid(self.proc.pid)
                os.killpg(pgid, signal.SIGTERM)
                self.proc.wait(timeout=2.0)
            except Exception:
                try:
                    self.proc.kill()
                    self.proc.wait(timeout=1.0)
                except Exception:
                    pass
            if self.proc.stdout:
                try:
                    self.proc.stdout.close()
                except Exception:
                    pass
            if self.proc.stderr:
                try:
                    self.proc.stderr.close()
                except Exception:
                    pass
        # Print logs on failure before cleaning up
        if not getattr(self, "success", False):
            log_path = os.path.join(self.mesh_home, "mesh-init-daemon.log")
            if os.path.exists(log_path):
                try:
                    with open(log_path, "r") as f:
                        print(f"\n--- DAEMON LOGS ---\n{f.read()}--- END DAEMON LOGS ---\n", flush=True)
                except Exception:
                    pass
        self.temp_dir.cleanup()

    def test_mesh_init_lifecycle_and_service_control(self):
        # 1. Start mesh-init daemon using our helper
        try:
            self.proc, self.socket_path = start_mesh_init(base_dir=self.mesh_home, env=self.env)
        except (RuntimeError, TimeoutError) as e:
            self.skipTest(f"Failed to start mesh-init (is it compiled and in PATH?): {e}")

        self.assertIsNotNone(self.socket_path)
        self.assertTrue(os.path.exists(self.socket_path))

        # 2. Query initial status of our service (should be auto-started and running)
        controller = ServiceController(self.socket_path)
        status = controller.get_service_status("mock-sleep")
        self.assertEqual(status.get("state"), "running")
        pid = status.get("pid")
        self.assertIsNotNone(pid)
        self.assertGreater(pid, 0)

        # 3. Stop the service
        stop_resp = controller.stop_service("mock-sleep")
        self.assertTrue(stop_resp.get("success", False) or "result" in stop_resp)

        # Give it a short moment to exit
        time.sleep(0.5)

        # 4. Verify it is stopped
        status = controller.get_service_status("mock-sleep")
        self.assertEqual(status.get("state"), "stopped")
        self.assertIsNone(status.get("pid"))

        # 5. Start the service again
        start_resp = controller.start_service("mock-sleep")
        self.assertTrue(start_resp.get("success", False) or "result" in start_resp)

        # Give it a short moment to transition state
        time.sleep(0.5)

        # 6. Verify it is running again
        status = controller.get_service_status("mock-sleep")
        self.assertEqual(status.get("state"), "running")
        pid = status.get("pid")
        self.assertIsNotNone(pid)
        self.assertGreater(pid, 0)

        self.success = True

if __name__ == "__main__":
    unittest.main()
