#!/usr/bin/env bash

set -e

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

src=${src:-${PROJECT_ROOT}}
out=${out:-${src}/target}

export NIX_PROFILE=${out}/ssh-mesh-profile
export PATH=${PATH}:${NIX_PROFILE}/bin

# Function to install the latest Nix with Flakes enabled
install_nix() {
    echo "Installing Nix..."
    if command -v nix >/dev/null 2>&1; then
        echo "Nix is already installed."
    else
        echo "Installing Nix using the Determinate Systems installer (enables flakes by default)..."
        curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
        echo ""
        echo "Nix installation complete!"
        echo "IMPORTANT: You may need to restart your shell or run the following to make the nix command available:"
        echo "source /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh"
    fi
    # curl -L https://nixos.org/nix/install | sh
    #   . /home/build/.nix-profile/etc/profile.d/nix.sh
}

# Function to build using Nix Flakes
build() {
    echo "Building the project using Nix Flake..."
    # Build default package
    nix --extra-experimental-features "nix-command flakes" build . -L
    echo "Build complete. Artifacts are in the ./result/ directory."
}

# Function to update Nix flake inputs
update_flake() {
    echo "Updating Nix flake inputs..."
    nix  flake update
}

# nix flake show PATH
# nix store gc
# 
# ls /nix/var/nix/gcroots/auto
## all profiles created in random places.

setup() {

  nix profile add linux --profile target/ssh-mesh-profile
  # list, upgrade
  export PATH="~/my-custom-dev-profile/bin:$PATH"

}

# Function to show help message
help() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  install_nix   Install the latest Nix with Flakes enabled (via Determinate Systems)"
    echo "  build         Build the project using Nix flake"
    echo "  update_flake  Update Nix flake inputs"
    echo "  run           Run the default package using Nix flake"
    echo "  help          Show this help message"
}

# Check if an argument was provided
if [ $# -eq 0 ]; then
    help
else
    # Execute the requested function
    "$@"
fi
