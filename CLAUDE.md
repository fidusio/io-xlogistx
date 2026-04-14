# Claude Code Instructions for io-xlogistx

## Project Overview

**io-xlogistx** is a multi-module Java Maven project providing security, networking, and HTTP utilities.

## Modules

| Module | Purpose |
|--------|---------|
| `core` | Core utilities, DNS client (dnsjava) |
| `common` | HTTP protocol handling, NIO networking, SMTP, DNS resolution |
| `http` | NIO HTTP/HTTPS server with WebSocket support |
| `shiro` | Apache Shiro security integration |
| `opsec` | PKI/X509 certificates, Bouncy Castle crypto, key management |
| `gui-audio` | GUI and audio utilities |
| `no-sneak` | **ACTIVE** - SSL/TLS & PQC security scanner, NMap network scanner |

## Current Focus: no-sneak Module

Building an SSL/TLS security scanner with Post-Quantum Cryptography (PQC) support.

**Key Documents:**
- `no-sneak/README.md` - Full requirements specification
- `no-sneak/ACTION-PLAN.md` - Implementation plan and progress tracking

**To resume work:** Read `no-sneak/ACTION-PLAN.md` for current status and next steps.

## Build Commands

```bash
# Build entire project
mvn clean install

# Build specific module with dependencies
mvn clean install -pl no-sneak -am

# Run tests
mvn test

# Run specific test
mvn test -pl no-sneak -Dtest=PQCScannerTest
```

## Key Dependencies

- **Bouncy Castle** (bcprov-jdk18on, bcpkix-jdk18on, bc-tls 1.83) - PKI, crypto, PQC support
- **dnsjava** - DNS resolution
- **Apache SSHD** - SSH client
- **Jakarta Mail** - Email support

## Code Style

- Java package base: `io.xlogistx`
- Prefer NIO for network operations (existing infrastructure in `common/nio`)
- Follow existing patterns in the codebase
- Use kebab-case for JSON/API field names

## Architectural Rules (IMPORTANT)

1. **All utility functions MUST go in `opsec/src/main/java/io/xlogistx/opsec/OPSecUtil.java`**
   - Certificate utilities
   - TLS/SSL helpers
   - Cryptographic operations
   - PQC functions

2. **Use Bouncy Castle exclusively** for all cryptographic operations
   - No alternative crypto libraries (e.g., liboqs)
   - BC already supports ML-KEM, ML-DSA for PQC

3. **TLS Implementation: Bouncy Castle TLS API**
   - **BC TLS API** for PQC scanning: Full control over key exchange, cipher suites
   - `PQCTlsClient` advertises PQC hybrid algorithms
   - `PQCTlsClientProtocol` intercepts key_share for detection

4. **Async HTTP: Use `HTTPURLCallback` + `HTTPNIOSocket`**
   - For any async HTTP operations (CRL downloads, OCSP requests, etc.)
   - Do NOT create custom blocking HTTP clients
   - `HTTPNIOSocket` wraps `NIOSocket` for truly event-driven, multiplexed HTTP
   - `HTTPURLCallback` handles both HTTP and HTTPS URLs

5. **Pure NIO Callback Architecture (No CompletableFuture/ForkJoinPool)**
   - `PQCCallback` is the main entry point — orchestrates scanning via callbacks, not futures
   - Phase 1 (handshake) uses `PQCNIOScanner` which calls `ScanCallback.onHandshakeComplete()`
   - Phase 2 (revocation, ciphers, versions) uses child probes (`CipherProbeCallback`, `VersionProbeCallback`)
   - Completion tracked via `AtomicInteger pendingCount` — when all tasks decrement to 0, result is delivered
   - Zero blocking, zero waiting — entirely event-driven on NIO selector thread

## Important Files

### PQC Scanner (Active Development)
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/PQCCallback.java` - **Main entry point** - Pure NIO callback orchestrator (replaces CompletableFuture)
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/PQCNIOScanner.java` - Phase 1 TLS handshake scanner (used by PQCCallback)
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/PQCScanResult.java` - Result container
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/ScanCallback.java` - Interface between PQCNIOScanner and PQCCallback
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/TLSProbeCallback.java` - Base class for NIO TLS probes
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/CipherProbeCallback.java` - NIO cipher enumeration probe
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/VersionProbeCallback.java` - NIO protocol version probe
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/NIORevocationChecker.java` - Async CRL/OCSP via HTTPURLCallback (callback-based, no CompletableFuture)
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/PQCTlsClient.java` - BC TLS client with PQC
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/PQCTlsClientProtocol.java` - Key exchange interception
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/PQCSSLStateMachine.java` - Handshake state machine
- `no-sneak/src/main/java/io/xlogistx/nosneak/services/QDZChecker.java` - REST endpoint (uses PQCCallback)

### Crypto & Certificates
- `opsec/src/main/java/io/xlogistx/opsec/OPSecUtil.java` - X509, PKI, PQC utilities
- `opsec/src/main/java/io/xlogistx/opsec/CRLReader.java` - CRL checking

### Networking & DNS
- `common/src/main/java/io/xlogistx/common/dns/DNSRegistrar.java` - DNS resolution with caching

### NMap Scanner (Network Scanning)
- `no-sneak/src/main/java/io/xlogistx/nosneak/nmap/NMapScanner.java` - Main scan orchestrator
- `no-sneak/src/main/java/io/xlogistx/nosneak/nmap/scan/tcp/TCPConnectScanEngine.java` - TCP scanning
- `no-sneak/src/main/java/io/xlogistx/nosneak/nmap/discovery/HostDiscovery.java` - Host discovery
- `no-sneak/src/main/java/io/xlogistx/nosneak/nmap/service/ServiceDetector.java` - Service detection

### HTTP/TLS Server
- `http/src/main/java/io/xlogistx/http/NIOHTTPServer.java` - HTTPS server with SSLContext

## PQC Scanner Quick Reference

### Detected PQC Algorithms
- **Key Exchange**: X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024
- **Signatures**: ML-DSA (Dilithium), Falcon, SPHINCS+

### PQCScanResult Fields
- `host`, `port`, `scan-id`, `scan-time-in-ms`
- `success`, `secure` (TLS detected)
- `tls-version`, `tls-version-pqc-capable`
- `key-exchange-type` (PQC_HYBRID, ECDHE, DHE, RSA)
- `key-exchange-algorithm`, `key-exchange-pqc-ready`
- `cipher-suite`
- `cert-signature-type`, `cert-signature-algorithm`
- `cert-public-key-type`, `cert-public-key-size`, `cert-pqc-ready`
- `cert-not-before`, `cert-not-after`, `cert-time-valid`
- `cert-chain-valid`, `cert-subject`, `cert-issuer`
- `overall-status` (READY, PARTIAL, NOT_READY, ERROR)
- `recommendations`

### REST Endpoint
```
GET /check-qdz/{domain}/{detailed}
```

## Tests

Key test files:
- `no-sneak/src/test/java/io/xlogistx/nosneak/scanners/PQCCallbackTest.java` - Tests for PQCCallback (main entry point)
- `no-sneak/src/test/java/io/xlogistx/nosneak/scanners/PQCScannerTest.java` - Tests for handshake and helper methods
- `common/src/test/java/io/xlogistx/common/dns/DNSRegistrarTest.java`

## Notes

- Platform: Windows (Cygwin available)
- IDE: IntelliJ IDEA
- Ask before making commits
