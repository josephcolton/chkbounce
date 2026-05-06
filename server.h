#ifndef SERVER_H
#define SERVER_H

/*
 * Start the server.  Binds to control_port on TCP, waits for one client,
 * negotiates the probe list, sets up probe sockets, then drives the
 * probe-by-probe protocol until the client sends MSG_DONE.
 */
void run_server(int control_port, int timeout_sec);

#endif /* SERVER_H */
