"""
SSH-Mesh Python Module

A Python implementation of ssh-mesh functionality using paramiko for SSH transport.
Provides secure SSH tunneling with port forwarding capabilities.
"""

__version__ = "0.1.0"
__author__ = "SSH-Mesh Team"

from .ssh_server import SSHMeshServer
from .ssh_client import SSHMeshClient

__all__ = ["SSHMeshServer", "SSHMeshClient"]
