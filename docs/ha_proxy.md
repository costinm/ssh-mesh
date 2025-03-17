# The Proxy Protocol

Istio ambient and others are using the proxy protocol to pass metadata between the L4 (ztunnel) and the user application
accepting a TCP stream. 

SSH and H2 tunnels are native implementations of the mesh protocols - if used on top of ambient, the expectation
is that ztunnel will handle any L4 authorization to make sure only Waypoints or Gateways can connect to H2 port,
and we may use the identity verified and injected by Waypoint or Gateways in the H2 transport. On SSH transport, it's all
cert based and end to end, so it doesn't matter.

That means for now the proxy protocol is not used.
