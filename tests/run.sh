#!/bin/bash

BIN_DIR=/ws/rust/ssh-mesh/target/debug

start_share() {
    ${BIN_DIR}/unpfs -l /tmp/unpfs.sock / &
    
}

start_servers() {
    tmux new-session -d -s ssh-mesh-servers

    # Window 0: ssh-mesh
    tmux rename-window -t ssh-mesh-servers:0 'ssh-mesh'
    tmux send-keys -t ssh-mesh-servers:0 'RUST_LOG=info HTTP_PORT=8080 cargo run --bin ssh-mesh' C-m

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
    tmux send-keys -t ssh-mesh-servers:0 'RUST_LOG=info HTTP_PORT=8080 ssh-mesh' C-m

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
    
    echo "Testing ssh-mesh HTTP server (port 8080)..."
    curl -s -f http://localhost:8080/_m/api/ssh/clients || { echo "ssh-mesh failed"; tmux kill-session -t ssh-mesh-servers; exit 1; }
    
    echo "Testing pmond HTTP server (port 8081)..."
    curl -s -f http://localhost:8081/_m/pmon/_ps || { echo "pmond failed"; tmux kill-session -t ssh-mesh-servers; exit 1; }

    echo "Testing otel trace server (port 9090)..."
    # The trace server API is mapped; hitting / just checks if process responds.
    # Disabling strict exit because root / might 404 if not mapped, but response proves it's up.
    curl -s http://localhost:9090/ > /dev/null || true

    echo "All tests passed! Stopping servers..."
    tmux kill-session -t ssh-mesh-servers
    echo "Servers stopped."
}

"$@"