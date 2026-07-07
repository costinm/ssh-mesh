import unittest
import os
import socket
import tempfile
import threading
import array
from dmesh import MeshListener, MeshClient, ProtocolFormat

class TestListener(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.socket_path = os.path.join(self.temp_dir.name, "test.sock")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_listener_uds_binding_and_auth(self):
        listener = MeshListener("test-app", listen_path=self.socket_path)
        
        accepted_event = threading.Event()
        results = {}

        def server_thread():
            conn, peer_uid = listener.accept()
            if conn:
                results["peer_uid"] = peer_uid
                # Echo raw data
                data = conn.recv(1024)
                conn.sendall(data)
                conn.close()
            accepted_event.set()

        t = threading.Thread(target=server_thread)
        t.start()

        # Connect client
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(self.socket_path)
        client.sendall(b"hello server")
        resp = client.recv(1024)
        client.close()

        accepted_event.wait(timeout=2.0)
        listener.close()

        self.assertEqual(resp, b"hello server")
        self.assertEqual(results.get("peer_uid"), os.getuid())

    def test_fd_passing_scm_rights(self):
        # Create Unix socket pair
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

        # Create a temp file to get a file descriptor to send
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_file.write(b"data to read")
        temp_file.flush()
        
        fd_to_send = temp_file.fileno()

        # Sender (parent) sends b"F" with the fd attached
        ancdata = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd_to_send]))]
        parent.sendmsg([b"F"], ancdata)

        # Receiver (child) receives
        fds = array.array("i")
        msg, received_ancdata, flags, addr = child.recvmsg(1, socket.CMSG_LEN(fds.itemsize))
        
        self.assertEqual(msg, b"F")
        received_fd = None
        for cmsg_level, cmsg_type, cmsg_data in received_ancdata:
            if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
                fds.frombytes(cmsg_data[:fds.itemsize])
                received_fd = fds[0]

        self.assertIsNotNone(received_fd)

        # Verify we can read from the received fd
        f = os.fdopen(received_fd, "rb")
        f.seek(0)
        content = f.read()
        self.assertEqual(content, b"data to read")
        f.close()
        temp_file.close()
        os.remove(temp_file.name)

        parent.close()
        child.close()

    def test_mock_systemd_socket_activation(self):
        # Create a dummy Unix socket to pass as activated fd
        dummy_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        dummy_sock.bind("\x00dummy-activation-test")
        dummy_sock.listen(1)
        fd = dummy_sock.fileno()

        # Set environment variables mimicking systemd activation
        os.environ["LISTEN_PID"] = str(os.getpid())
        os.environ["LISTEN_FDS"] = "1"

        # By systemd standard, activated FDs start at 3.
        # We can duplicate our dummy socket's fd into fd 3.
        # (Save original fd 3 if it existed to restore later)
        orig_fd_3 = None
        try:
            orig_fd_3 = os.dup(3)
        except OSError:
            pass

        os.dup2(fd, 3)

        try:
            # Create MeshListener without listen_path; should claim fd 3
            listener = MeshListener("activated-app")
            self.assertIsNotNone(listener.socket)
            self.assertEqual(listener.socket.family, socket.AF_UNIX)
            listener.close()
        finally:
            # Clean up env
            os.environ.pop("LISTEN_PID", None)
            os.environ.pop("LISTEN_FDS", None)
            dummy_sock.close()
            try:
                os.close(3)
            except OSError:
                pass
            if orig_fd_3 is not None:
                os.dup2(orig_fd_3, 3)
                os.close(orig_fd_3)


if __name__ == "__main__":
    unittest.main()
