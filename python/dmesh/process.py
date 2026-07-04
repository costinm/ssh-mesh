import os
import time
import subprocess
import logging
from .client import MeshClient
from .jsonl import ProtocolFormat

logger = logging.getLogger("dmesh.process")

def resolve_control_socket_path(base_dir=None) -> str:
    """Resolves the control socket path for mesh-init."""
    mesh_home = base_dir or os.environ.get("MESH_HOME")
    
    if not mesh_home:
        # Check standard user locations
        home = os.environ.get("HOME")
        if home:
            # Check ~/.ssh/control.sock or ~/.ssh/mesh.sock
            p1 = os.path.join(home, ".ssh/control.sock")
            if os.path.exists(p1):
                return p1
            p2 = os.path.join(home, ".ssh/mesh.sock")
            if os.path.exists(p2):
                return p2
        
        # Check fallback path relative to current working directory
        uid = os.getuid()
        if uid == 0:
            mesh_home_dir = "/home/mesh-init"
        else:
            mesh_home_dir = os.path.join(os.getcwd(), "mesh/home/mesh-init")
    else:
        mesh_home_dir = os.path.join(mesh_home, "home/mesh-init")

    # Standard run path is run/mesh-init/control.sock or run/control.sock or etc.
    paths_to_try = [
        os.path.join(mesh_home_dir, "run/control.sock"),
        os.path.join(mesh_home_dir, "run/mesh-init/control.sock"),
        os.path.join(mesh_home_dir, "control.sock"),
    ]
    
    # If MESH_RUN_BASE is explicitly set
    mesh_run_base = os.environ.get("MESH_RUN_BASE")
    if mesh_run_base:
        paths_to_try.insert(0, os.path.join(mesh_run_base, "mesh-init/mesh.sock"))
        paths_to_try.insert(0, os.path.join(mesh_run_base, "mesh-init/control.sock"))

    for p in paths_to_try:
        if os.path.exists(p):
            return p
            
    # Default fallback
    return paths_to_try[0]

def is_mesh_init_alive(socket_path: str) -> bool:
    """Checks if mesh-init is alive by querying status via UDS control socket."""
    if not os.path.exists(socket_path):
        return False
    try:
        client = MeshClient(socket_path, protocol_format=ProtocolFormat.JSONRPC)
        # Querying general status
        resp = client.request("status", req_id=999)
        if resp and ("result" in resp or "success" in resp or "data" in resp):
            return True
    except Exception as e:
        logger.debug("mesh-init check alive failed on %s: %s", socket_path, e)
    return False

def start_mesh_init(base_dir=None, env=None) -> tuple[subprocess.Popen, str]:
    """Starts mesh-init daemon process as the user."""
    run_env = dict(os.environ)
    if env:
        run_env.update(env)

    socket_path = run_env.get("MESH_INIT_SOCK")
    if not socket_path:
        socket_path = resolve_control_socket_path(base_dir)
        run_env["MESH_INIT_SOCK"] = socket_path
    
    if is_mesh_init_alive(socket_path):
        logger.info("mesh-init is already running at %s", socket_path)
        return None, socket_path

    # Ensure parent directories exist
    os.makedirs(os.path.dirname(socket_path), exist_ok=True)

    cmd = ["mesh-init"]

    
    if base_dir:
        run_env["MESH_HOME"] = base_dir
        # Ensure correct socket path is used
        run_env["MESH_RUN_BASE"] = os.path.join(base_dir, "home/mesh-init/run")

    stdout_file = None
    stderr_file = None
    log_path = None
    if base_dir:
        log_path = os.path.join(base_dir, "mesh-init-daemon.log")
        stdout_file = open(log_path, "w")
        stderr_file = stdout_file
    else:
        stdout_file = subprocess.DEVNULL
        stderr_file = subprocess.DEVNULL

    try:
        proc = subprocess.Popen(
            cmd,
            env=run_env,
            stdout=stdout_file,
            stderr=stderr_file,
            preexec_fn=os.setsid # run in its own process group
        )
    finally:
        if base_dir and stdout_file:
            stdout_file.close()

    # Wait for the control socket to become active and respond
    deadline = time.time() + 10.0
    while time.time() < deadline:
        if proc.poll() is not None:
            log_content = ""
            if log_path and os.path.exists(log_path):
                try:
                    with open(log_path, "r") as f:
                        log_content = f.read()
                except Exception:
                    pass
            raise RuntimeError(
                f"mesh-init exited prematurely with code {proc.returncode}.\n"
                f"Logs:\n{log_content}"
            )
        
        # Use the configured socket path directly
        if is_mesh_init_alive(socket_path):
            logger.info("mesh-init successfully started at %s", socket_path)
            return proc, socket_path
        time.sleep(0.2)


    raise TimeoutError("Timeout waiting for mesh-init to start and respond on control UDS")

class ServiceController:
    """Enables service management (start/stop/status) through mesh-init control socket."""
    def __init__(self, socket_path: str):
        self.socket_path = socket_path
        self.client = MeshClient(socket_path, protocol_format=ProtocolFormat.JSONRPC)

    def start_service(self, name: str, args: list = None, env: dict = None) -> dict:
        params = {"name": name}
        if args:
            params["args"] = args
        if env:
            params["env"] = env
        resp = self.client.request("start", params=params)
        return resp

    def stop_service(self, name: str, signal: int = None) -> dict:
        params = {"name": name}
        if signal is not None:
            params["signal"] = signal
        resp = self.client.request("stop", params=params)
        return resp

    def get_service_status(self, name: str) -> dict:
        resp = self.client.request("status", params={"name": name})
        # Check if JSON-RPC result or Flat JSON data
        if "result" in resp:
            return resp["result"]
        elif "data" in resp:
            return resp["data"]
        return resp
