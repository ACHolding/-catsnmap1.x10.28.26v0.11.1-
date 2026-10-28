#!/usr/bin/env bash
#
# cat's nmap 1.1
# A small TCP connect() port scanner written in bash.
# Works on Linux, macOS, FreeBSD, OpenBSD and NetBSD (bash must be installed).
# On Windows, use "cat's nmap 1.1.ps1" instead.
# Run it with bash (or sh; it re-launches itself under bash).
#
# Usage: bash "cat's nmap 1.1.sh" [options] <host> [host ...]
#
#   -p <spec>    ports: 80 | 1-1024 | 22,80,443 | - (all 1-65535) | mixes of these
#                default: a list of common service ports
#   -F           fast mode: scan a shorter list of common ports
#   -T <n>       parallel probes (default 100)
#   -t <sec>     per-port connect timeout in seconds (default 1)
#   -Pn          skip host discovery (scan even if ping fails)
#   -sV          grab banners from open ports (light service detection)
#   -o <file>    also write the report to a file
#   -v           verbose: also list closed and filtered ports
#   -V           print version
#   -h           show this help
#
# Only scan machines you own or have explicit permission to test.

# Re-launch under bash if started with sh (e.g. "sh script.sh").
if [ -z "${BASH_VERSION:-}" ]; then
    exec bash "$0" "$@"
fi

set -u

VERSION="1.1"
PORT_SPEC=""
FAST=0
PARALLEL=100
TIMEOUT=1
SKIP_PING=0
GRAB_BANNER=0
OUTFILE=""
VERBOSE=0
RESULTS=""
SORTED=""
PORTS=""

COMMON_PORTS="21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,1433,1521,3306,3389,5432,5900,6379,8000,8080,8443,8888,9200,27017"
FAST_PORTS="21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"

die() {
    echo "cat's nmap: error: $*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
cat's nmap 1.1 - TCP connect port scanner

Usage: bash "cat's nmap 1.1.sh" [options] <host> [host ...]

  -p <spec>    ports: 80 | 1-1024 | 22,80,443 | - (all) | mixes of these
  -F           fast mode (short list of common ports)
  -T <n>       parallel probes (default 100)
  -t <sec>     connect timeout per port (default 1)
  -Pn          skip host discovery
  -sV          grab banners from open ports
  -o <file>    also write results to a file
  -v           show closed and filtered ports too
  -V           show version
  -h           show this help

Only scan systems you own or have permission to test.
EOF
    exit 0
}

# Turn a port spec like "22,80,8000-8100,-" into one port per line.
expand_ports() {
    local spec=$1 part start end p
    local IFS=,
    for part in $spec; do
        if [ "$part" = "-" ]; then
            start=1
            end=65535
        elif [ "${part#*-}" != "$part" ]; then
            start=${part%-*}
            end=${part#*-}
        else
            start=$part
            end=$part
        fi
        case "$start$end" in
            *[!0-9]*|"") die "bad port spec: $part" ;;
        esac
        if [ "$start" -lt 1 ] || [ "$end" -gt 65535 ] || [ "$start" -gt "$end" ]; then
            die "port range out of bounds: $part"
        fi
        p=$start
        while [ "$p" -le "$end" ]; do
            echo "$p"
            p=$((p + 1))
        done
    done | sort -un
}

# Run a command with the connect timeout. Uses timeout/gtimeout if present,
# otherwise a pure-bash watchdog (macOS has no timeout by default).
# Returns 124 if the command was killed for taking too long.
run_limited() {
    local pid killer rc
    if command -v timeout >/dev/null 2>&1; then
        timeout "$TIMEOUT" "$@"
        return $?
    fi
    if command -v gtimeout >/dev/null 2>&1; then
        gtimeout "$TIMEOUT" "$@"
        return $?
    fi

    "$@" &
    pid=$!
    ( sleep "$TIMEOUT"; kill -9 "$pid" 2>/dev/null ) &
    killer=$!
    wait "$pid" 2>/dev/null
    rc=$?
    kill "$killer" 2>/dev/null
    wait "$killer" 2>/dev/null
    if [ "$rc" -eq 137 ] || [ "$rc" -eq 143 ]; then
        return 124
    fi
    return $rc
}

# Attempt a TCP connection.
# Exit codes: 0 = open, 124 = timed out (filtered), anything else = refused (closed).
probe() {
    local host=$1 port=$2
    run_limited bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$host" "$port" 2>/dev/null
}

# Read a short banner from an open port. HTTP-style ports get a HEAD request first.
banner() {
    local host=$1 port=$2 req=""
    case $port in
        80|8000|8080|8888)
            req=$(printf 'HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n' "$host")
            ;;
    esac
    run_limited bash -c '
        exec 3<>"/dev/tcp/$1/$2" || exit 1
        if [ -n "$3" ]; then printf "%s" "$3" >&3; fi
        IFS= read -r -t 1 line <&3
        printf "%s" "$line" | tr -d "\r" | cut -c1-70
    ' _ "$host" "$port" "$req" 2>/dev/null
}

service_name() {
    case $1 in
        21) echo ftp ;;
        22) echo ssh ;;
        23) echo telnet ;;
        25) echo smtp ;;
        53) echo domain ;;
        80) echo http ;;
        110) echo pop3 ;;
        111) echo rpcbind ;;
        135) echo msrpc ;;
        139) echo netbios-ssn ;;
        143) echo imap ;;
        443) echo https ;;
        445) echo microsoft-ds ;;
        465) echo smtps ;;
        587) echo submission ;;
        993) echo imaps ;;
        995) echo pop3s ;;
        1433) echo ms-sql ;;
        1521) echo oracle ;;
        1723) echo pptp ;;
        3306) echo mysql ;;
        3389) echo ms-wbt-server ;;
        5432) echo postgresql ;;
        5900) echo vnc ;;
        6379) echo redis ;;
        8000|8888) echo http-alt ;;
        8080) echo http-proxy ;;
        8443) echo https-alt ;;
        9200) echo elasticsearch ;;
        27017) echo mongodb ;;
        *) echo unknown ;;
    esac
}

# Scan one port and append "port<TAB>state<TAB>banner" to the results file.
scan_port() {
    local host=$1 port=$2 rc state line=""
    probe "$host" "$port"
    rc=$?
    case $rc in
        0)
            state=open
            if [ "$GRAB_BANNER" -eq 1 ]; then
                line=$(banner "$host" "$port")
            fi
            ;;
        124) state=filtered ;;
        *)   state=closed ;;
    esac
    printf '%s\t%s\t%s\n' "$port" "$state" "$line" >> "$RESULTS"
}

scan_host() {
    local target=$1 ip port start n_open=0 n_closed=0 n_filt=0 state line svc

    ip=""
    if command -v getent >/dev/null 2>&1; then   # Linux only; macOS/BSD fall back to the name
        ip=$(getent hosts "$target" 2>/dev/null | awk 'NR==1 {print $1}')
    fi
    ip=${ip:-$target}

    if [ "$SKIP_PING" -eq 0 ]; then
        # -c 1 works on Linux, macOS, FreeBSD, OpenBSD and NetBSD; the timeout wrapper handles waits
        if ! run_limited ping -c 1 "$target" >/dev/null 2>&1; then
            echo "Note: $target ($ip) did not answer ping and may be down or blocking ICMP."
            echo "      Use -Pn to scan it anyway."
            echo
            return
        fi
    fi

    echo "Starting cat's nmap $VERSION at $(date '+%Y-%m-%d %H:%M:%S') on $(uname -sr 2>/dev/null)"
    echo "Scan report for $target ($ip)"
    start=$(date +%s)

    : > "$RESULTS"
    for port in $PORTS; do
        while [ "$(jobs -rp | wc -l)" -ge "$PARALLEL" ]; do
            sleep 0.05
        done
        scan_port "$target" "$port" &
    done
    wait

    sort -n "$RESULTS" > "$SORTED"

    printf '%-10s %-10s %s\n' PORT STATE SERVICE
    while IFS=$'\t' read -r port state line; do
        case $state in
            open)
                n_open=$((n_open + 1))
                svc=$(service_name "$port")
                if [ -n "$line" ]; then
                    printf '%-10s %-10s %s\n' "$port/tcp" open "$svc  [$line]"
                else
                    printf '%-10s %-10s %s\n' "$port/tcp" open "$svc"
                fi
                ;;
            filtered)
                n_filt=$((n_filt + 1))
                if [ "$VERBOSE" -eq 1 ]; then printf '%-10s %-10s\n' "$port/tcp" filtered; fi
                ;;
            closed)
                n_closed=$((n_closed + 1))
                if [ "$VERBOSE" -eq 1 ]; then printf '%-10s %-10s\n' "$port/tcp" closed; fi
                ;;
        esac
    done < "$SORTED"

    echo
    if [ "$n_open" -eq 0 ]; then
        echo "No open ports found on $target."
    fi
    echo "Not shown: $n_closed closed, $n_filt filtered ports"
    echo "cat's nmap done: 1 host scanned in $(( $(date +%s) - start ))s"
    echo
}

# ---- argument parsing -------------------------------------------------------

TARGETS=()
while [ $# -gt 0 ]; do
    case $1 in
        -p)
            [ $# -ge 2 ] || die "-p needs a value"
            PORT_SPEC=$2; shift 2 ;;
        -F)
            FAST=1; shift ;;
        -T)
            [ $# -ge 2 ] || die "-T needs a value"
            PARALLEL=$2; shift 2 ;;
        -t)
            [ $# -ge 2 ] || die "-t needs a value"
            TIMEOUT=$2; shift 2 ;;
        -Pn)
            SKIP_PING=1; shift ;;
        -sV)
            GRAB_BANNER=1; shift ;;
        -o)
            [ $# -ge 2 ] || die "-o needs a file name"
            OUTFILE=$2; shift 2 ;;
        -v)
            VERBOSE=1; shift ;;
        -V|--version)
            echo "cat's nmap $VERSION"; exit 0 ;;
        -h|--help)
            usage ;;
        -*)
            die "unknown option: $1 (try -h)" ;;
        *)
            TARGETS+=("$1"); shift ;;
    esac
done

[ "${#TARGETS[@]}" -gt 0 ] || usage
case $PARALLEL in *[!0-9]*|"") die "-T must be a positive integer" ;; esac
case $TIMEOUT in *[!0-9]*|"") die "-t must be a positive integer" ;; esac
[ "$PARALLEL" -ge 1 ] || die "-T must be at least 1"
[ "$TIMEOUT" -ge 1 ] || die "-t must be at least 1"

if [ "$FAST" -eq 1 ]; then
    PORT_SPEC=$FAST_PORTS
fi
[ -n "$PORT_SPEC" ] || PORT_SPEC=$COMMON_PORTS

PORTS=$(expand_ports "$PORT_SPEC")
[ -n "$PORTS" ] || die "no ports to scan"

RESULTS=$(mktemp) || die "could not create temp file"
SORTED="$RESULTS.sorted"
trap 'rm -f "$RESULTS" "$SORTED"' EXIT

if [ -n "$OUTFILE" ]; then
    : > "$OUTFILE" || die "cannot write to $OUTFILE"
    exec > >(tee "$OUTFILE")
fi

for t in "${TARGETS[@]}"; do
    scan_host "$t"
done

wait
