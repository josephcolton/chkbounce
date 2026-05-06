#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "protocol.h"
#include "server.h"
#include "client.h"

#define MODE_UNSET  0
#define MODE_SERVER 1
#define MODE_CLIENT 2

static const char default_tcp_str[] = "22,80,443,8080,8443";
static const char default_udp_str[] = "53,123,161";
static const char default_icmp_str[] = "0-255";

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s -s [-p PORT] [--timeout=SECS]\n"
        "  %s -c SERVER [-p PORT] [-i[TYPES]] [-t[PORTS]] [-u[PORTS]] [--timeout=SECS]\n"
        "\n"
        "  SERVER may be a hostname or dotted-decimal IPv4 address.\n"
        "\n"
        "  Ranges use comma-separated values and inclusive N-M ranges:\n"
        "    -i0,3,8-11      ICMP types 0, 3, 8, 9, 10, 11\n"
        "    -t22,80,443     TCP ports 22, 80, 443\n"
        "    -u53,123-130    UDP ports 53, 123 through 130\n"
        "\n"
        "Options:\n"
        "  -s, --server           Run in server mode\n"
        "  -c, --client           Run in client mode\n"
        "  -p, --port=NUM         Control channel TCP port (default: %d)\n"
        "      --timeout=NUM      Per-probe timeout in seconds (default: %d)\n"
        "  -i[TYPES], --icmp[=TYPES]  ICMP type probes (default: 0-255)\n"
        "  -t[PORTS], --tcp[=PORTS]   TCP port probes  (default: %s)\n"
        "  -u[PORTS], --udp[=PORTS]   UDP port probes  (default: %s)\n"
        "  -o FILE,   --output=FILE   Write report to FILE in addition to stdout\n",
        prog, prog,
        DEFAULT_CONTROL_PORT, DEFAULT_TIMEOUT,
        default_tcp_str, default_udp_str);
}

/*
 * Parse a comma-and-range string like "22,25-40,80" into a malloc'd int array.
 * Ranges are inclusive.  Returns NULL on failure or empty input.
 */
static int *parse_range_list(const char *str, int *count) {
    *count = 0;
    if (!str || !*str) return NULL;

    /* First pass: count total elements so we allocate exactly the right size */
    char *tmp = strdup(str);
    if (!tmp) return NULL;
    int n = 0;
    char *tok = strtok(tmp, ",");
    while (tok) {
        char *dash = strchr(tok, '-');
        if (dash && dash != tok) {        /* range: lo-hi */
            int lo = atoi(tok), hi = atoi(dash + 1);
            n += (hi >= lo) ? (hi - lo + 1) : 1;
        } else {
            n++;
        }
        tok = strtok(NULL, ",");
    }
    free(tmp);

    if (n == 0) return NULL;
    int *arr = malloc(n * sizeof(int));
    if (!arr) return NULL;

    /* Second pass: fill the array */
    tmp = strdup(str);
    if (!tmp) { free(arr); return NULL; }
    int idx = 0;
    tok = strtok(tmp, ",");
    while (tok && idx < n) {
        char *dash = strchr(tok, '-');
        if (dash && dash != tok) {
            int lo = atoi(tok), hi = atoi(dash + 1);
            if (hi >= lo)
                for (int v = lo; v <= hi && idx < n; v++) arr[idx++] = v;
            else
                arr[idx++] = lo;
        } else {
            arr[idx++] = atoi(tok);
        }
        tok = strtok(NULL, ",");
    }
    free(tmp);
    *count = idx;
    return arr;
}

int main(int argc, char **argv) {
    int   mode         = MODE_UNSET;
    int   control_port = DEFAULT_CONTROL_PORT;
    int   timeout_sec  = DEFAULT_TIMEOUT;
    char *server_host  = NULL;
    char *output_file  = NULL;
    const char *icmp_str = NULL;
    const char *tcp_str  = NULL;
    const char *udp_str  = NULL;

    static struct option long_opts[] = {
        { "server",  no_argument,       NULL, 's' },
        { "client",  no_argument,       NULL, 'c' },
        { "port",    required_argument, NULL, 'p' },
        { "timeout", required_argument, NULL, 'T' },
        { "icmp",    optional_argument, NULL, 'i' },
        { "tcp",     optional_argument, NULL, 't' },
        { "udp",     optional_argument, NULL, 'u' },
        { "output",  required_argument, NULL, 'o' },
        { NULL, 0, NULL, 0 }
    };

    int opt, lidx;
    /* Note: optional_argument for short opts requires no space (-t80, not -t 80) */
    while ((opt = getopt_long(argc, argv, "scp:T:i::t::u::o:", long_opts, &lidx)) != -1) {
        switch (opt) {
        case 's': mode = MODE_SERVER; break;
        case 'c': mode = MODE_CLIENT; break;
        case 'p': control_port = atoi(optarg); break;
        case 'T': timeout_sec  = atoi(optarg); break;
        case 'i': icmp_str   = optarg ? optarg : default_icmp_str; break;
        case 't': tcp_str    = optarg ? optarg : default_tcp_str;  break;
        case 'u': udp_str    = optarg ? optarg : default_udp_str;  break;
        case 'o': output_file = optarg; break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    /* SERVER_HOST is the first non-option argument in client mode */
    if (mode == MODE_CLIENT && optind < argc)
        server_host = argv[optind];

    if (mode == MODE_UNSET) { usage(argv[0]); return 1; }

    if (control_port <= 0 || control_port > 65535) {
        fprintf(stderr, "Invalid port: %d\n", control_port);
        return 1;
    }
    if (timeout_sec <= 0) {
        fprintf(stderr, "Invalid timeout: %d\n", timeout_sec);
        return 1;
    }

    if (mode == MODE_SERVER) {
        run_server(control_port, timeout_sec);
        return 0;
    }

    /* ---- client mode ---- */
    if (!server_host) {
        fprintf(stderr, "Client mode requires a server hostname or IP.\n");
        usage(argv[0]);
        return 1;
    }

    /* If no protocol selected, default to all three */
    if (!icmp_str && !tcp_str && !udp_str) {
        icmp_str = default_icmp_str;
        tcp_str  = default_tcp_str;
        udp_str  = default_udp_str;
    }

    int  icmp_count = 0, tcp_count = 0, udp_count = 0;
    int *icmp_types = NULL, *tcp_ports = NULL, *udp_ports = NULL;

    if (icmp_str) icmp_types = parse_range_list(icmp_str, &icmp_count);
    if (tcp_str)  tcp_ports  = parse_range_list(tcp_str,  &tcp_count);
    if (udp_str)  udp_ports  = parse_range_list(udp_str,  &udp_count);

    run_client(server_host, control_port, timeout_sec,
               icmp_types, icmp_count,
               tcp_ports,  tcp_count,
               udp_ports,  udp_count,
               output_file);

    free(icmp_types);
    free(tcp_ports);
    free(udp_ports);
    return 0;
}
