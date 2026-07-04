import os
import sys
import socket
import struct
import fcntl
import array
import logging

logger = logging.getLogger("dmesh.listener")

def set_cloexec(fd: int):
    try:
        flags = fcntl.fcntl(fd, fcntl.F_GETFD)
        fcntl.fcntl(fd, fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)
    except Exception as e:
        logger.warning("Failed to set FD_CLOEXEC on fd %d: %s", fd, e)

class StdioConnection:
    def __init__(self):
        self.stdin = sys.stdin.buffer
        self.stdout = sys.stdout.buffer
        self.closed = False

    def recv(self, bufsize):
        try:
            data = self.stdin.read(bufsize)
            return data
        except Exception:
            return b""

    def send(self, data):
        try:
            self.stdout.write(data)
            self.stdout.flush()
            return len(data)
        except Exception:
            return 0

    def sendall(self, data):
        self.send(data)

    def close(self):
        self.closed = True

    def recvmsg(self, *args, **kwargs):
        raise NotImplementedError("FD passing not supported on stdio")

    def sendmsg(self, *args, **kwargs):
        raise NotImplementedError("FD passing not supported on stdio")

class MeshListener:
    def __init__(self, app_name: str, listen_path: str = None):
        self.app_name = app_name
        self.listen_path = listen_path
        self.socket = None
        self.stdio_mode = False
        self.stdio_yielded = False
        self._detect_and_bind()

    def _detect_and_bind(self):
        # 1. Check systemd socket activation
        listen_pid = os.environ.get("LISTEN_PID")
        if not listen_pid or int(listen_pid) == os.getpid():
            listen_fds_str = os.environ.get("LISTEN_FDS")
            if listen_fds_str:
                try:
                    num_fds = int(listen_fds_str)
                    if num_fds > 0:
                        # Claim the first Unix socket FD (usually fd 3)
                        for fd in range(3, 3 + num_fds):
                            # Try to wrap as AF_UNIX socket and verify
                            try:
                                s = socket.fromfd(fd, socket.AF_UNIX, socket.SOCK_STREAM)
                                s.getsockname() # will fail if not AF_UNIX or not valid
                                set_cloexec(fd)
                                self.socket = s
                                logger.info("Using systemd-activated Unix socket on fd %d", fd)
                                return
                            except Exception:
                                pass
                except ValueError:
                    pass

        # 2. Check for MESH_RES_DIR or manual listen path
        if self.listen_path:
            actual_path = self.listen_path
            abstract = False
            if actual_path.startswith("_"):
                # Abstract socket namespace
                actual_path = "\x00" + actual_path[1:]
                abstract = True
            elif not actual_path.startswith("/"):
                # Relative to run dir
                run_dir = os.environ.get("MESH_RUN_DIR", f"/run/mesh/{self.app_name}")
                os.makedirs(run_dir, exist_ok=True)
                actual_path = os.path.join(run_dir, actual_path)

            if not abstract and os.path.exists(actual_path):
                try:
                    os.remove(actual_path)
                except OSError:
                    pass

            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.bind(actual_path)
            s.listen(128)
            set_cloexec(s.fileno())

            if not abstract:
                try:
                    os.chmod(actual_path, 0o666)
                except OSError:
                    pass

            self.socket = s
            logger.info("Listening on Unix socket: %s", self.listen_path)
            return

        # 3. Default to Stdio
        logger.info("Serving over stdin/stdout")
        self.stdio_mode = True

    def accept(self) -> tuple[object, int]:
        """Accepts a connection.

        Returns (connection_object, peer_uid).
        """
        if self.stdio_mode:
            if self.stdio_yielded:
                # Stdio serves exactly once
                return None, None
            self.stdio_yielded = True
            return StdioConnection(), os.getuid()

        while True:
            try:
                conn, addr = self.socket.accept()
                set_cloexec(conn.fileno())
            except Exception as e:
                logger.error("Accept failed: %s", e)
                return None, None

            # Authenticate UDS connection
            peer_uid = self._get_peer_uid(conn)
            if peer_uid is None:
                logger.warning("Failed to obtain peer UID, closing connection")
                conn.close()
                continue

            if not self._is_uid_authorized(peer_uid):
                logger.warning("Unauthorized connection from UID %d, closing connection", peer_uid)
                conn.close()
                continue

            return conn, peer_uid

    def _get_peer_uid(self, conn: socket.socket) -> int:
        try:
            # struct ucred: pid (int32), uid (uint32), gid (uint32)
            creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            pid, uid, gid = struct.unpack("3I", creds)
            return uid
        except Exception as e:
            logger.debug("SO_PEERCRED failed: %s", e)
            return None

    def _is_uid_authorized(self, uid: int) -> bool:
        if uid == 0 or uid == os.getuid():
            return True

        def get_env_uid(name, default):
            val = os.environ.get(name)
            if val is None:
                return default
            val = val.strip().lower()
            if val in ("none", "off", ""):
                return None
            try:
                return int(val)
            except ValueError:
                return default

        system_uid = get_env_uid("MESH_SYSTEM_UID", 1000)
        sshd_uid = get_env_uid("MESH_TRUSTED_SSHD_UID", 103)
        ssh_mesh_uid = get_env_uid("MESH_SSH_MESH_UID", 150)

        if system_uid is not None and uid == system_uid:
            return True
        if sshd_uid is not None and uid == sshd_uid:
            return True
        if ssh_mesh_uid is not None and uid == ssh_mesh_uid:
            return True

        return False

    def close(self):
        if self.socket:
            self.socket.close()
            if self.listen_path and not self.listen_path.startswith("_") and not self.listen_path.startswith("\x00"):
                try:
                    os.remove(self.listen_path)
                except OSError:
                    pass
