# Network IO

This package wraps few core network functions to create 'mesh' equivalents.

Listeners can be remote (ssh -R) and may use mesh protocols (HA-Proxy with ztunnel and others, ssh, etc), native crypto, h2 tunneling, etc to get metadata including the 'real' address and integrate with the security layers.



Proxy is a TCP proxy, commonly used for mesh.

Few helpers - buf and pool - deal with the needs of the proxy, and streams
has wrappers.



