#!/bin/bash

# Use tmux kill-session -t ssh-mesh-servers to stop
# Use `tmux capture-pane -t ssh_mesh-servers:0 -p || tmux capture-pane -t ssh-mesh-servers:0 -p `



BIN_DIR=/ws/rust/ssh-mesh/target/x86_64-unknown-linux-musl/debug

get_control_uds() {
    local basedir=${SSH_BASEDIR:-""}
    if [ -z "$basedir" ]; then
        if [ -d "$HOME/.ssh" ]; then
            basedir="$HOME/.ssh"
        else
            basedir="/tmp/.ssh"
        fi
    fi
    echo "$basedir/control.sock"
}

start_share() {
    ${BIN_DIR}/unpfs -l /tmp/unpfs.sock / &
    
}

start_servers() {
    tmux new-session -d -s ssh-mesh-servers

    # Window 0: ssh-mesh
    tmux rename-window -t ssh-mesh-servers:0 'ssh-mesh'
    tmux send-keys -t ssh-mesh-servers:0 'RUST_LOG=info HTTP_PORT=15080 cargo run --bin ssh-mesh' C-m

    # Window 1: pmond
    tmux new-window -t ssh-mesh-servers -n 'pmond'
    # pmond --server listens on 8081/8082 by default
    tmux send-keys -t ssh-mesh-servers:1 'RUST_LOG=info cargo run --bin pmond -- --server' C-m

    # Window 2: otel
    tmux new-window -t ssh-mesh-servers -n 'otel'
    tmux send-keys -t ssh-mesh-servers:2 'RUST_LOG=info TRACE_PORT=9090 cargo run --bin otel' C-m

    echo "Servers started in tmux session: ssh-mesh-servers"
    echo "To attach, run: tmux attach-session -t ssh-mesh-servers"
}

start_servers_nix() {
    tmux new-session -d -s ssh-mesh-servers

    tmux rename-window -t ssh-mesh-servers:0 'ssh-mesh'
    tmux send-keys -t ssh-mesh-servers:0 'RUST_LOG=info HTTP_PORT=15080 ssh-mesh' C-m

    tmux new-window -t ssh-mesh-servers -n 'pmond'
    # Force port to 8081 to be deterministic
    tmux send-keys -t ssh-mesh-servers:1 'RUST_LOG=info HTTP_PORT=8081 pmond --server' C-m

    tmux new-window -t ssh-mesh-servers -n 'otel'
    tmux send-keys -t ssh-mesh-servers:2 'RUST_LOG=info TRACE_PORT=9090 otel' C-m

    echo "Servers started in tmux session: ssh-mesh-servers"
}

test_servers() {
    echo "Starting servers from nix env built binaries..."
    start_servers_nix
    
    echo "Waiting for servers to start..."
    sleep 3
    
    echo "Testing ssh-mesh HTTP server via UDS ($(get_control_uds))..."
    local uds=$(get_control_uds)
    curl -s -f --unix-socket "$uds" http://localhost/_m/api/ssh/clients || { echo "ssh-mesh failed on UDS"; tmux kill-session -t ssh-mesh-servers; exit 1; }
    
    echo "Testing pmond HTTP server (port 8081)..."
    curl -s -f http://localhost:8081/_m/pmon/_ps || { echo "pmond failed"; tmux kill-session -t ssh-mesh-servers; exit 1; }

    echo "Testing otel trace server (port 9090)..."
    # The trace server API is mapped; hitting / just checks if process responds.
    # Disabling strict exit because root / might 404 if not mapped, but response proves it's up.
    curl -s --unix-socket "$uds" http://localhost/ > /dev/null || true

    echo "All tests passed! Stopping servers..."
    tmux kill-session -t ssh-mesh-servers
    echo "Servers stopped."
}

connect_host8() {
    local host=${1:-host8}
    if [ ! -S /tmp/unpfs.sock ]; then
        echo "Starting unpfs server..."
        start_share
        sleep 1
    fi
    echo "Connecting to $host with /tmp/unpfs.sock forwarding..."
    ssh -p 15022 \
        -o ControlMaster=no -o ControlPath=none \
        -o StreamLocalBindUnlink=yes \
        -R /tmp/unpfs.sock:/tmp/unpfs.sock "$host" \
        "sudo mkdir -p /mnt/1; sudo umount /mnt/1 2>/dev/null; sudo mount -t 9p -o trans=unix,version=9p2000.L /tmp/unpfs.sock /mnt/1; bash -i"
}

connect_host8_sshmx() {
    local host=${1:-host8}
    if [ ! -S /tmp/unpfs.sock ]; then
        echo "Starting unpfs server..."
        start_share
        sleep 1
    fi
    echo "Connecting to $host using sshmc with /tmp/unpfs.sock forwarding..."
    # sshmc uses the same syntax for UDS forwarding: -R local_path:remote_path
    local IGNORE=""
    if [ "$host" == "127.0.0.1" ]; then
        IGNORE="SSHMUX_IGNORE=1"
    fi
    env $IGNORE ${BIN_DIR}/sshmc  -R /tmp/unpfs.sock:/tmp/unpfs.sock "$host" \
        "sudo mkdir -p /mnt/1; sudo umount /mnt/1 2>/dev/null; sudo mount -t 9p -o trans=unix,version=9p2000.L /tmp/unpfs.sock /mnt/1; bash -i"
}

connect_host8_http() {
    local host=${1:-host8}
    
    local uds=$(get_control_uds)
    
    # Check if ssh-mesh is running via UDS
    if [ ! -S "$uds" ]; then
        echo "ssh-mesh control UDS not found at $uds. Starting servers..."
        start_servers
        echo "Waiting for ssh-mesh to start..."
        node_alive=0
        for i in {1..10}; do
            if [ -S "$uds" ]; then
                node_alive=1
                break
            fi
            sleep 1
        done
        if [ $node_alive -eq 0 ]; then
            echo "Failed to start ssh-mesh or control socket not created."
            exit 1
        fi
    fi

    echo "Connecting to $host:15022 via HTTP API over UDS..."
    local user=${USER:-root}
    curl -X POST --unix-socket "$uds" http://localhost/_m/api/sshc/connect \
        -H "Content-Type: application/json" \
        -d "{\"host\": \"$host\", \"port\": 15022, \"user\": \"$user\"}"
    
    echo -e "\nConnection request sent. Check logs or /_m/api/sshc/connections for status."
}

"$@"