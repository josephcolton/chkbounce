#ifndef SERVER_H
#define SERVER_H

/*
 * Start the server.  Listens on control_port and handles clients one at a
 * time, forever: negotiate, then drive the probe-by-probe protocol until the
 * client sends MSG_DONE.  family is AF_UNSPEC (IPv4 and IPv6), AF_INET or
 * AF_INET6; each session uses the address family of its client.
 */
void run_server(int control_port, int timeout_sec, int family);

#endif /* SERVER_H */
