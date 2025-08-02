# Python helpers for ssh
import paramiko
import socket


class MySSHServer(paramiko.ServerInterface):
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_port_forward_request(self, address, port):
        # Allow reverse port forwarding requests
        return True

    def check_auth_password(self, username, password):
        # Implement your authentication logic
        return paramiko.AUTH_SUCCESSFUL

