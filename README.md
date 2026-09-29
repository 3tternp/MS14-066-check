# winshock-test

A small, dependency-light Bash script that checks whether a TLS endpoint is
**likely unpatched against Winshock — MS14-066 / CVE-2014-6321** — the 2014
remote-code-execution flaw in Microsoft's Schannel (Secure Channel) stack.

This is a rebuilt and modernised version of the original
[anexia-it/winshock-test](https://github.com/anexia-it/winshock-test)
(MIT licensed), with argument parsing, timeouts, verbose and JSON output,
proper exit codes, and dependency checks.

> **This tool does not exploit anything.** It performs a *behavioural* check
> against the target's supported TLS ciphers (and, on port 443, the HTTP
> server banner) to infer patch status. It is read-only reconnaissance
> intended for authorised patch verification and audits.

## How it works

The MS14-066 rollup patch introduced four new Schannel GCM cipher suites:

| OpenSSL name                 | IANA name                             |
| ---------------------------- | ------------------------------------- |
| `DHE-RSA-AES256-GCM-SHA384`  | `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384` |
| `DHE-RSA-AES128-GCM-SHA256`  | `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256` |
| `AES256-GCM-SHA384`          | `TLS_RSA_WITH_AES_256_GCM_SHA384`     |
| `AES128-GCM-SHA256`          | `TLS_RSA_WITH_AES_128_GCM_SHA256`     |

The script asks the target to negotiate each of these, one at a time, with
`openssl s_client`:

- **All four negotiated →** the rollup is present → **patched**.
- **None negotiated →** a hint the host may be **unpatched** (on port 443 an
  IIS 8.0/8.5 banner strengthens the finding).
- **Some but not all →** **inconclusive** — usually a hardened or custom
  cipher policy rather than a patch signal.

## Requirements

- `bash` 4+
- `openssl` (any modern build; the script auto-detects `-tls1_2` support)
- `timeout` (GNU coreutils)

## Usage

```bash
chmod +x winshock_test.sh

# HTTPS
./winshock_test.sh www.example.com 443

# RDP (raw TLS)
./winshock_test.sh 10.0.0.1 3389

# Verbose per-cipher output
./winshock_test.sh --verbose 10.0.0.2 443

# Machine-readable output for pipelines / SIEM ingestion
./winshock_test.sh --json --timeout 5 10.0.0.2 443
```

### Options

| Option              | Description                                         |
| ------------------- | --------------------------------------------------- |
| `-t, --timeout <s>` | Per-connection timeout in seconds (default `10`)    |
| `-s, --sni <name>`  | SNI server name (defaults to host if it's a name)   |
| `-j, --json`        | Emit machine-readable JSON only                     |
| `-v, --verbose`     | Show each individual cipher probe                   |
| `--openssl <path>`  | Use a specific `openssl` binary                     |
| `--no-color`        | Disable coloured output                             |
| `-h, --help`        | Show help                                           |
| `-V, --version`     | Print version                                       |

### Exit codes

| Code | Meaning                                                     |
| ---- | ---------------------------------------------------------- |
| `0`  | Patched (all four MS14-066 ciphers negotiated)             |
| `1`  | Likely vulnerable (none of the four negotiated)            |
| `2`  | Inconclusive (partial support, unreachable, or usage error)|

### JSON output

```json
{
  "host": "10.0.0.2",
  "port": 443,
  "reachable": true,
  "verdict": "patched",
  "ciphers_supported": 4,
  "ciphers_total": 4,
  "banner": "Microsoft-IIS/8.5",
  "ciphers": {
    "DHE-RSA-AES256-GCM-SHA384": "supported",
    "DHE-RSA-AES128-GCM-SHA256": "supported",
    "AES256-GCM-SHA384": "supported",
    "AES128-GCM-SHA256": "supported"
  },
  "exit_code": 0
}
```

## Caveats & false positives

This is a heuristic, not a definitive scan:

- **SSL offloading / load balancers / reverse proxies** terminate TLS with
  their own cipher stack, so results reflect the front-end, not the Windows
  host behind it.
- **Custom cipher policies** can disable these GCM suites on a fully patched
  server (yielding a false "vulnerable"), or enable equivalents on an
  unpatched one.
- **Modern, hardened servers** that offer only ECDHE / TLS 1.3 will report
  "likely vulnerable" even though MS14-066 is irrelevant to them. Interpret
  results only for legacy Windows Server 2012 / 2012 R2 IIS and RDP endpoints.

Always confirm a positive finding against the host's actual patch level
(`Get-HotFix`, WSUS/SCCM, or the update history) before acting on it.

## Authorised use only

Run this only against systems you own or are explicitly authorised to test.
Unauthorised scanning may be illegal in your jurisdiction.

## References

- [MS14-066 — Vulnerability in Schannel could allow remote code execution](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-066)
- CVE-2014-6321
- Original tool: [anexia-it/winshock-test](https://github.com/anexia-it/winshock-test)

## License

MIT — see [LICENSE](LICENSE). Original work © 2014 ANEXIA
Internetdienstleistungs GmbH; rebuild © 2026 contributors.
