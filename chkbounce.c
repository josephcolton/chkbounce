#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <sys/random.h>
#include <sys/socket.h>

#include "protocol.h"
#include "server.h"
#include "client.h"

#define MODE_UNSET  0
#define MODE_SERVER 1
#define MODE_CLIENT 2

static const char default_tcp_str[] = "22,80,443,8080,8443";
static const char default_udp_str[] = "53,123,161";
static const char default_icmp_str[] = "0-255";

#include "version.h"

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s -s [-4|-6] [-p PORT] [--timeout=SECS]\n"
        "  %s -c SERVER [-4|-6] [-p PORT] [-i[TYPES]] [-t[PORTS]] [-u[PORTS]] [-r|-b] [-n N] [-q]\n"
        "             [--shuffle[=SEED]] [--meta KEY=VALUE]... [--timeout=SECS]\n"
        "             [-o FILE] [--csv=FILE] [--json=FILE]\n"
        "\n"
        "  SERVER may be a hostname or a numeric IPv4/IPv6 address.\n"
        "  In IPv6 sessions, -i TYPES are ICMPv6 type numbers.\n"
        "\n"
        "  Ranges use comma-separated values and inclusive N-M ranges:\n"
        "    -i0,3,8-11      ICMP types 0, 3, 8, 9, 10, 11 (code 0, or --code)\n"
        "    -i3:0-15,4:1-2  Type 3 codes 0-15, and type 4 codes 1 and 2\n"
        "    -t22,80,443     TCP ports 22, 80, 443\n"
        "    -u53,123-130    UDP ports 53, 123 through 130\n"
        "\n"
        "Options:\n"
        "  -s, --server           Run in server mode\n"
        "  -c, --client           Run in client mode\n"
        "  -4, --ipv4             Use IPv4 only (server: accept IPv4 clients only)\n"
        "  -6, --ipv6             Use IPv6 only (server: accept IPv6 clients only)\n"
        "  -p, --port=NUM         Control channel TCP port (default: %d)\n"
        "      --timeout=NUM      Per-probe timeout in seconds (default: %d)\n"
        "  -i[TYPES], --icmp[=TYPES]  ICMP type probes (default: 0-255); TYPE:CODE\n"
        "                             items choose codes\n"
        "             --code=N        Code for ICMP items without one (default 0)\n"
        "  -t[PORTS], --tcp[=PORTS]   TCP port probes  (default: %s)\n"
        "  -u[PORTS], --udp[=PORTS]   UDP port probes  (default: %s)\n"
        "  -r,        --reverse       Server sends probes to client (server -> client)\n"
        "  -b,        --both          Test each probe in both directions\n"
        "  -n N,      --count=N       Sweep the probe list N times (1-%d, default 1)\n"
        "  -q,        --quote         Send ICMP error types quoting a primer datagram\n"
        "             --shuffle[=SEED]  Randomize probe order each round (seed is recorded;\n"
        "                             give the same SEED to reproduce an order)\n"
        "  -m KEY=VALUE, --meta=KEY=VALUE  Record a tag with the results (repeatable;\n"
        "                             KEY is letters, digits, '_', '.', '-')\n"
        "  -o FILE,   --output=FILE   Write report to FILE in addition to stdout\n"
        "             --csv=FILE      Append results to FILE as CSV (header added if new)\n"
        "             --json=FILE     Write results to FILE as JSON\n"
        "  -V,        --version       Print version and exit\n",
        prog, prog,
        DEFAULT_CONTROL_PORT, DEFAULT_TIMEOUT,
        default_tcp_str, default_udp_str, MAX_ATTEMPTS);
}

#define MAX_META     32
#define MAX_META_KEY 63

/* KEY=VALUE with a short identifier-like KEY and a printable VALUE */
static int valid_meta(const char *s) {
    const char *eq = strchr(s, '=');
    if (!eq || eq == s || eq - s > MAX_META_KEY) return 0;
    for (const char *p = s; p < eq; p++)
        if (!isalnum((unsigned char)*p) && *p != '_' && *p != '.' && *p != '-')
            return 0;
    for (const char *p = eq + 1; *p; p++)
        if (!isprint((unsigned char)*p)) return 0;
    return 1;
}

/* Seed for --shuffle without a value: kernel randomness, else time and pid */
static unsigned long long random_seed(void) {
    unsigned long long v;
    if (getrandom(&v, sizeof(v), 0) == (ssize_t)sizeof(v)) return v;
    return (unsigned long long)time(NULL) ^ ((unsigned long long)getpid() << 32);
}

/*
 * Parse "N" or "N-M" (inclusive, each 0..255) at *p; advance *p past it.
 * Returns 0 on success, -1 on a malformed or out-of-range span.
 */
static int parse_span(const char **p, int *lo, int *hi) {
    char *end;
    if (!isdigit((unsigned char)**p)) return -1;
    long a = strtol(*p, &end, 10), b = a;
    if (*end == '-') {
        const char *q = end + 1;
        if (!isdigit((unsigned char)*q)) return -1;
        b = strtol(q, &end, 10);
    }
    if (a < 0 || b > 255 || a > b) return -1;
    *lo = (int)a; *hi = (int)b; *p = end;
    return 0;
}

/*
 * Parse an ICMP list: comma-separated items TYPES[:CODES], where TYPES and
 * CODES are "N" or "N-M" (0..255).  Items without CODES use default_code.
 * Expands to parallel malloc'd arrays of (type, code), type-major.
 * Returns 0 on success, -1 (with a message) on a syntax error.
 */
static int parse_icmp_list(const char *str, int default_code,
                           int **types, int **codes, int *count) {
    int n = 0, cap = 64;
    int *t = malloc(cap * sizeof(int)), *c = malloc(cap * sizeof(int));
    const char *p = str, *item = str;
    if (!t || !c) goto fail;

    while (*p) {
        int tlo, thi, clo = default_code, chi = default_code;
        item = p;
        if (parse_span(&p, &tlo, &thi) < 0) goto bad;
        if (*p == ':') {
            p++;
            if (parse_span(&p, &clo, &chi) < 0) goto bad;
        }
        if (*p != ',' && *p != '\0') goto bad;
        for (int ty = tlo; ty <= thi; ty++)
            for (int co = clo; co <= chi; co++) {
                if (n == cap) {
                    cap *= 2;
                    int *nt = realloc(t, cap * sizeof(int));
                    if (!nt) goto fail;
                    t = nt;
                    int *nc = realloc(c, cap * sizeof(int));
                    if (!nc) goto fail;
                    c = nc;
                }
                t[n] = ty; c[n] = co; n++;
            }
        if (*p == ',') {
            p++;
            if (!*p) { item = "(trailing comma)"; goto bad; }
        }
    }
    if (n == 0) {
        fprintf(stderr, "Empty ICMP list\n");
        goto fail;
    }
    *types = t; *codes = c; *count = n;
    return 0;
bad:
    fprintf(stderr, "Invalid ICMP list at '%s': use TYPE[-TYPE][:CODE[-CODE]],... "
                    "with values 0-255\n", item);
fail:
    free(t); free(c);
    return -1;
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
    char *csv_file     = NULL;
    char *json_file    = NULL;
    int   directions   = DIR_FORWARD;
    int   family       = AF_UNSPEC;
    int   count        = 1;
    int   quote        = 0;
    int   default_code = 0;
    int   do_shuffle   = 0;
    unsigned long long seed = 0;
    const char *meta[MAX_META];
    int   nmeta        = 0;
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
        { "reverse", no_argument,       NULL, 'r' },
        { "both",    no_argument,       NULL, 'b' },
        { "ipv4",    no_argument,       NULL, '4' },
        { "ipv6",    no_argument,       NULL, '6' },
        { "csv",     required_argument, NULL, 'C' },
        { "json",    required_argument, NULL, 'J' },
        { "version", no_argument,       NULL, 'V' },
        { "count",   required_argument, NULL, 'n' },
        { "quote",   no_argument,       NULL, 'q' },
        { "shuffle", optional_argument, NULL, 'S' },
        { "meta",    required_argument, NULL, 'm' },
        { "code",    required_argument, NULL, 'K' },
        { NULL, 0, NULL, 0 }
    };

    int opt, lidx;
    /* Note: optional_argument for short opts requires no space (-t80, not -t 80) */
    while ((opt = getopt_long(argc, argv, "scp:T:i::t::u::o:rb46Vn:qm:", long_opts, &lidx)) != -1) {
        switch (opt) {
        case 's': mode = MODE_SERVER; break;
        case 'c': mode = MODE_CLIENT; break;
        case 'p': control_port = atoi(optarg); break;
        case 'T': timeout_sec  = atoi(optarg); break;
        case 'i': icmp_str   = optarg ? optarg : default_icmp_str; break;
        case 't': tcp_str    = optarg ? optarg : default_tcp_str;  break;
        case 'u': udp_str    = optarg ? optarg : default_udp_str;  break;
        case 'o': output_file = optarg; break;
        case 'r': directions = DIR_REVERSE; break;
        case 'b': directions = DIR_BOTH;    break;
        case '4': family = AF_INET;         break;
        case '6': family = AF_INET6;        break;
        case 'C': csv_file  = optarg; break;
        case 'J': json_file = optarg; break;
        case 'n': count = atoi(optarg); break;
        case 'q': quote = 1;            break;
        case 'K': {
            char *end;
            long v = strtol(optarg, &end, 10);
            if (!*optarg || *end || v < 0 || v > 255) {
                fprintf(stderr, "Invalid code: %s (must be 0-255)\n", optarg);
                return 1;
            }
            default_code = (int)v;
            break;
        }
        case 'S':
            do_shuffle = 1;
            if (optarg) {
                char *end;
                seed = strtoull(optarg, &end, 10);
                if (!*optarg || *end) {
                    fprintf(stderr, "Invalid shuffle seed: %s\n", optarg);
                    return 1;
                }
            } else {
                seed = random_seed();
            }
            break;
        case 'm':
            if (nmeta == MAX_META) {
                fprintf(stderr, "Too many --meta tags (max %d)\n", MAX_META);
                return 1;
            }
            if (!valid_meta(optarg)) {
                fprintf(stderr, "Invalid --meta '%s': use KEY=VALUE, KEY of 1-%d letters, "
                                "digits, '_', '.', '-', VALUE printable\n",
                        optarg, MAX_META_KEY);
                return 1;
            }
            meta[nmeta++] = optarg;
            break;
        case 'V': printf("chkbounce %s\n", CHKBOUNCE_VERSION); return 0;
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
    if (count < 1 || count > MAX_ATTEMPTS) {
        fprintf(stderr, "Invalid count: %d (must be 1-%d)\n", count, MAX_ATTEMPTS);
        return 1;
    }

    /*
     * Line-buffer stdout so progress and server logs reach a file or pipe
     * as they happen instead of being lost in the buffer when killed.
     */
    setvbuf(stdout, NULL, _IOLBF, 0);

    if (mode == MODE_SERVER) {
        run_server(control_port, timeout_sec, family);
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
    int *icmp_types = NULL, *icmp_codes = NULL, *tcp_ports = NULL, *udp_ports = NULL;

    if (icmp_str && parse_icmp_list(icmp_str, default_code,
                                    &icmp_types, &icmp_codes, &icmp_count) < 0)
        return 1;
    if (tcp_str)  tcp_ports  = parse_range_list(tcp_str,  &tcp_count);
    if (udp_str)  udp_ports  = parse_range_list(udp_str,  &udp_count);

    struct client_opts o = {
        .server_host  = server_host,
        .control_port = control_port,
        .timeout_sec  = timeout_sec,
        .family       = family,
        .directions   = directions,
        .icmp_types   = icmp_types, .icmp_count = icmp_count,
        .icmp_codes   = icmp_codes,
        .tcp_ports    = tcp_ports,  .tcp_count  = tcp_count,
        .udp_ports    = udp_ports,  .udp_count  = udp_count,
        .count        = count,
        .quote        = quote,
        .shuffle      = do_shuffle,
        .seed         = seed,
        .meta         = meta,
        .nmeta        = nmeta,
        .output_file  = output_file,
        .csv_file     = csv_file,
        .json_file    = json_file,
    };
    run_client(&o);

    free(icmp_types);
    free(icmp_codes);
    free(tcp_ports);
    free(udp_ports);
    return 0;
}
