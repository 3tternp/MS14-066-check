#!/usr/bin/env bash
#
# winshock_test.sh — MS14-066 (Winshock / CVE-2014-6321) patch detector
# ---------------------------------------------------------------------
# MS14-066 shipped four new Schannel GCM cipher suites. If a TLS endpoint
# negotiates all four, the rollup patch is present. If it offers none of
# them, that is a *hint* (not proof) that the host is unpatched.
#
# This tool does NOT exploit the vulnerability. It only fingerprints
# cipher support (and, on 443, the HTTP server banner) to infer patch
# status. It is a defensive assessment aid — behavioural, remote, and
# read-only.
#
# Rebuilt/modernised from the original ANEXIA emergency-response script
# (https://github.com/anexia-it/winshock-test), MIT licensed.
#
set -o errexit
set -o nounset
set -o pipefail

readonly VERSION="2.0.0"
readonly PROG="${0##*/}"

# --- The four cipher suites introduced by the MS14-066 rollup ----------
# OpenSSL names -> IANA names:
#   DHE-RSA-AES256-GCM-SHA384  = TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
#   DHE-RSA-AES128-GCM-SHA256  = TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
#   AES256-GCM-SHA384          = TLS_RSA_WITH_AES_256_GCM_SHA384
#   AES128-GCM-SHA256          = TLS_RSA_WITH_AES_128_GCM_SHA256
readonly WINSHOCK_CIPHERS=(
  "DHE-RSA-AES256-GCM-SHA384"
  "DHE-RSA-AES128-GCM-SHA256"
  "AES256-GCM-SHA384"
  "AES128-GCM-SHA256"
)

# --- Defaults ----------------------------------------------------------
OPENSSL_BIN="${OPENSSL_BIN:-$(command -v openssl || true)}"
TIMEOUT="${WINSHOCK_TIMEOUT:-10}"
JSON=false
VERBOSE=false
USE_COLOR=true
SNI=""

# --- Colours -----------------------------------------------------------
c_reset=""; c_red=""; c_grn=""; c_yel=""; c_blu=""; c_bold=""
setup_colors() {
  if $USE_COLOR && [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
    c_reset=$'\033[0m'; c_red=$'\033[31m'; c_grn=$'\033[32m'
    c_yel=$'\033[33m'; c_blu=$'\033[34m'; c_bold=$'\033[1m'
  fi
}

# --- Logging -----------------------------------------------------------
log()  { $JSON || printf '%s\n' "$*"; }
vlog() { $VERBOSE && ! $JSON && printf '%s[*]%s %s\n' "$c_blu" "$c_reset" "$*" >&2 || true; }
err()  { printf '%s[!]%s %s\n' "$c_red" "$c_reset" "$*" >&2; }

usage() {
  cat <<EOF
${c_bold}$PROG v$VERSION${c_reset} — Winshock (MS14-066 / CVE-2014-6321) patch detector

${c_bold}USAGE${c_reset}
  $PROG [options] <host> <port>

${c_bold}ARGUMENTS${c_reset}
  host          Target hostname or IP (connect directly, not via a load balancer)
  port          TLS port to probe (e.g. 443 for HTTPS, 3389 for RDP)

${c_bold}OPTIONS${c_reset}
  -t, --timeout <sec>   Per-connection timeout in seconds (default: $TIMEOUT)
  -s, --sni <name>      SNI server name to send (default: host if it is a name)
  -j, --json            Emit machine-readable JSON only
  -v, --verbose         Show each cipher probe result
      --openssl <path>  Path to the openssl binary to use
      --no-color        Disable coloured output
  -h, --help            Show this help and exit
  -V, --version         Print version and exit

${c_bold}EXAMPLES${c_reset}
  $PROG 10.0.0.1 3389
  $PROG www.example.com 443
  $PROG --json --timeout 5 10.0.0.2 443

${c_bold}EXIT CODES${c_reset}
  0  Patched          (all four MS14-066 ciphers negotiated)
  1  Likely vulnerable (none of the four ciphers negotiated)
  2  Inconclusive      (partial support, unreachable, or usage/dependency error)

${c_bold}NOTE${c_reset}
  This is a behavioural check. SSL-offloading, custom cipher policies, or
  a proxy in front of the target can cause false positives/negatives.
  Absence of the ciphers is a hint to investigate — not confirmation.
EOF
}

die() { err "$*"; exit 2; }

# --- Argument parsing --------------------------------------------------
parse_args() {
  local -a pos=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -t|--timeout)  TIMEOUT="${2:?--timeout needs a value}"; shift 2 ;;
      -s|--sni)      SNI="${2:?--sni needs a value}"; shift 2 ;;
      -j|--json)     JSON=true; shift ;;
      -v|--verbose)  VERBOSE=true; shift ;;
      --openssl)     OPENSSL_BIN="${2:?--openssl needs a value}"; shift 2 ;;
      --no-color)    USE_COLOR=false; shift ;;
      -h|--help)     setup_colors; usage; exit 0 ;;
      -V|--version)  printf '%s %s\n' "$PROG" "$VERSION"; exit 0 ;;
      --)            shift; while [[ $# -gt 0 ]]; do pos+=("$1"); shift; done ;;
      -*)            die "Unknown option: $1 (see --help)" ;;
      *)             pos+=("$1"); shift ;;
    esac
  done

  [[ ${#pos[@]} -eq 2 ]] || { setup_colors; usage; exit 2; }
  HOST="${pos[0]}"; PORT="${pos[1]}"

  [[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT >= 1 && PORT <= 65535 )) \
    || die "Invalid port: $PORT"
  [[ "$TIMEOUT" =~ ^[0-9]+$ ]] && (( TIMEOUT >= 1 )) \
    || die "Invalid timeout: $TIMEOUT"
}

is_ip() { [[ "$1" =~ ^[0-9]+(\.[0-9]+){3}$ ]] || [[ "$1" == *:* ]]; }

# --- Environment checks ------------------------------------------------
OPENSSL_HAS_TLS12=false
check_deps() {
  [[ -n "$OPENSSL_BIN" && -x "$OPENSSL_BIN" ]] \
    || die "openssl not found — install it or pass --openssl <path>"
  command -v timeout >/dev/null 2>&1 \
    || die "'timeout' (coreutils) is required"
  if "$OPENSSL_BIN" s_client -help 2>&1 | grep -q -- '-tls1_2'; then
    OPENSSL_HAS_TLS12=true
  fi
  vlog "Using $("$OPENSSL_BIN" version 2>/dev/null) at $OPENSSL_BIN"
}

# --- Core probes -------------------------------------------------------
# Run a single handshake attempt restricted to one TLS 1.2 cipher.
run_openssl() {
  local cipher="$1"
  local -a args=(s_client -connect "${HOST}:${PORT}" -cipher "$cipher")
  $OPENSSL_HAS_TLS12 && args+=(-tls1_2)
  [[ -n "$SNI" ]] && args+=(-servername "$SNI")
  timeout "$TIMEOUT" "$OPENSSL_BIN" "${args[@]}" </dev/null 2>&1 || true
}

# Distinguish "cannot reach target" from "cipher not offered".
# Returns: 0 supported, 1 not supported, 3 unreachable.
probe_cipher() {
  local cipher="$1" out
  out="$(run_openssl "$cipher")"

  if grep -qiE 'connect:errno=|getaddrinfo|Connection refused|Name or service not known|no route to host' <<<"$out"; then
    return 3
  fi
  # Negotiated cipher appears as "Cipher is X" and/or "Cipher    : X".
  if grep -qiE "Cipher[[:space:]]*(is|:)[[:space:]]*${cipher}(\b|$)" <<<"$out" \
     && ! grep -qiE 'Cipher[[:space:]]*(is|:)[[:space:]]*(NONE|\(NONE\)|0000)' <<<"$out"; then
    return 0
  fi
  return 1
}

# Grab the HTTP Server: banner (HTTPS only) to corroborate an IIS target.
# Always returns 0 so a missing banner never trips `set -e`.
grab_banner() {
  local -a args=(s_client -connect "${HOST}:${PORT}" -quiet)
  [[ -n "$SNI" ]] && args+=(-servername "$SNI")
  local out
  out="$(printf 'HEAD / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n' "${SNI:-$HOST}" \
        | timeout "$TIMEOUT" "$OPENSSL_BIN" "${args[@]}" 2>/dev/null || true)"
  printf '%s' "$out" | grep -i '^Server:' | head -n1 | tr -d '\r' \
    | sed 's/^[Ss]erver:[[:space:]]*//' || true
  return 0
}

# --- Reporting ---------------------------------------------------------
json_escape() { local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; printf '%s' "$s"; }

main() {
  parse_args "$@"
  setup_colors
  check_deps

  [[ -z "$SNI" ]] && ! is_ip "$HOST" && SNI="$HOST"

  log ""
  log "${c_bold}Winshock (MS14-066) check${c_reset} — ${HOST}:${PORT}"
  log "$(printf '%.0s-' {1..48})"

  local supported=0 unsupported=0 unreachable=0
  local -a results=()

  for cipher in "${WINSHOCK_CIPHERS[@]}"; do
    set +e
    probe_cipher "$cipher"
    local rc=$?
    set -e
    case $rc in
      0) supported=$((supported+1)); results+=("$cipher:supported")
         vlog "${c_grn}supported${c_reset}   $cipher" ;;
      1) unsupported=$((unsupported+1)); results+=("$cipher:unsupported")
         vlog "${c_red}unsupported${c_reset} $cipher" ;;
      3) unreachable=$((unreachable+1)); results+=("$cipher:unreachable")
         vlog "${c_yel}unreachable${c_reset} $cipher" ;;
    esac
  done

  # If every probe failed to connect, the target is unreachable.
  if (( unreachable == ${#WINSHOCK_CIPHERS[@]} )); then
    if $JSON; then
      printf '{"host":"%s","port":%s,"reachable":false,"verdict":"unreachable","ciphers_supported":0,"exit_code":2}\n' \
        "$(json_escape "$HOST")" "$PORT"
    else
      err "Target unreachable on ${HOST}:${PORT} — no service, wrong port, or firewalled."
    fi
    exit 2
  fi

  local banner=""
  if [[ "$PORT" == "443" ]]; then
    banner="$(grab_banner)"
    [[ -n "$banner" ]] && vlog "Server banner: $banner"
  fi

  # --- Verdict ---------------------------------------------------------
  local verdict code
  if (( supported == ${#WINSHOCK_CIPHERS[@]} )); then
    verdict="patched"; code=0
  elif (( supported == 0 )); then
    verdict="likely_vulnerable"; code=1
  else
    verdict="inconclusive"; code=2
  fi

  if $JSON; then
    local ciphers_json="" first=true
    for r in "${results[@]}"; do
      $first || ciphers_json+=","
      ciphers_json+="\"$(json_escape "${r%%:*}")\":\"${r##*:}\""
      first=false
    done
    printf '{"host":"%s","port":%s,"reachable":true,"verdict":"%s","ciphers_supported":%d,"ciphers_total":%d,"banner":"%s","ciphers":{%s},"exit_code":%d}\n' \
      "$(json_escape "$HOST")" "$PORT" "$verdict" "$supported" "${#WINSHOCK_CIPHERS[@]}" \
      "$(json_escape "$banner")" "$ciphers_json" "$code"
    exit "$code"
  fi

  log ""
  log "MS14-066 ciphers negotiated: ${supported}/${#WINSHOCK_CIPHERS[@]}"
  [[ -n "$banner" ]] && log "HTTP server banner:          ${banner}"
  log ""
  case $verdict in
    patched)
      log "${c_grn}${c_bold}[+] PATCHED${c_reset} — all four MS14-066 ciphers are supported." ;;
    likely_vulnerable)
      log "${c_red}${c_bold}[-] LIKELY VULNERABLE${c_reset} — none of the MS14-066 ciphers are supported."
      [[ "$banner" == *IIS* ]] && log "    Banner matches IIS, which strengthens the finding."
      log "    Verify manually: SSL-offloading or a custom cipher policy can mimic this." ;;
    inconclusive)
      log "${c_yel}${c_bold}[?] INCONCLUSIVE${c_reset} — only ${supported}/${#WINSHOCK_CIPHERS[@]} ciphers negotiated."
      log "    A fully patched default config offers all four; partial support usually"
      log "    means a hardened/custom cipher policy. Confirm patch level on the host." ;;
  esac
  log ""
  exit "$code"
}

main "$@"
