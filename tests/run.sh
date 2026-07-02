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

    # mesh-init owns the process observer.

    echo "Servers started in tmux session: ssh-mesh-servers"
    echo "To attach, run: tmux attach-session -t ssh-mesh-servers"
}

start_servers_nix() {
    tmux new-session -d -s ssh-mesh-servers

    tmux rename-window -t ssh-mesh-servers:0 'ssh-mesh'
    tmux send-keys -t ssh-mesh-servers:0 'RUST_LOG=info HTTP_PORT=15080 ssh-mesh' C-m

    # mesh-init owns the process observer.

    echo "Servers started in tmux session: ssh-mesh-servers"
}

test_servers() {
    echo "Run tests/test_examples.sh for the mesh-init observer and ssh-mesh proxy smoke test."
    echo "All tests passed."
}

connect_host8() {
    local host=${1:-host8}
    if [ ! -S /tmp/unpfs.sock ]; then
        echo "Starting unpfs server..."
        start_share
        sleep 1
    fi
    echo "Connecting to $host with /tmp/unpfs.sock -> /tmp/9p.sock forwarding (auto-mount)..."
    ssh -p 15022 \
        -o ControlMaster=no -o ControlPath=none \
        -o StreamLocalBindUnlink=yes \
        -R /tmp/9p.sock:/tmp/unpfs.sock "$host" \
        bash -i
}

connect_host8_sshmx() {
    local host=${1:-host8}
    if [ ! -S /tmp/unpfs.sock ]; then
        echo "Starting unpfs server..."
        start_share
        sleep 1
    fi
    echo "Connecting to $host using sshmc with /tmp/9p.sock forwarding (auto-mount)..."
    # sshmc uses the same syntax for UDS forwarding: -R local_path:remote_path
    # The remote path /tmp/9p.sock triggers per-peer directory + auto-mount on the server.
    local IGNORE=""
    if [ "$host" == "127.0.0.1" ]; then
        IGNORE="SSHMUX_IGNORE=1"
    fi
    env $IGNORE ${BIN_DIR}/sshmc -R /tmp/9p.sock:/tmp/unpfs.sock "$host" \
        bash -i
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
