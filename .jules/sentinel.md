# Sentinel's Journal

## 2025-10-26 - IPv6 Support in Plain TCP Driver
**Vulnerability:** The `nsd_ptcp` (Plain TCP) driver's `get_socket_info` function incorrectly assumes `AF_INET` (IPv4) for all connections, using `struct sockaddr_in` and `inet_ntop(AF_INET, ...)`.
**Learning:** This results in incorrect or garbage IP addresses being logged for IPv6 connections, potentially misleading administrators during debugging or security incidents (e.g., failed connection attempts from IPv6 sources).
**Prevention:** Always use `struct sockaddr_storage` for address storage and check `ss_family` (or `sa_family`) before casting to `sockaddr_in` or `sockaddr_in6`. Use `INET6_ADDRSTRLEN` for IP string buffers.
