# NoSneak SSL/TLS & PQC Scanner - Action Plan

> Last Updated: 2026-02-04
> Status: **Phase 3 Complete** - Pure NIO Callback Architecture (No CompletableFuture/ForkJoinPool)

---

## Recent Completed Work (2026-02-04)

### Refactor: Pure NIO Callback Architecture — Eliminated CompletableFuture/ForkJoinPool

Replaced the `CompletableFuture`-based scanner pipeline with a pure NIO callback architecture.
`PQCCallback` is now the main entry point, orchestrating child probes via callbacks on the NIO selector thread.

#### New Files Created
- [x] **ScanCallback.java** - Interface between PQCNIOScanner and PQCCallback
  - `onHandshakeComplete(PQCSessionConfig)` - Phase 1 complete
  - `onError(String)` - Error handling
- [x] **TLSProbeCallback.java** - Abstract base class for NIO TLS probes
  - Extends `TCPSessionCallback`, handles non-blocking TLS handshake
  - Subclasses implement: `createTlsClient()`, `onProbeSuccess()`, `onProbeFailure()`
- [x] **CipherProbeCallback.java** - NIO cipher enumeration probe
  - Iterative chain: connect → note selection → remove → repeat
  - Reports via `CipherProbeListener`
- [x] **VersionProbeCallback.java** - NIO protocol version probe
  - Tests individual TLS/SSL versions
  - Reports via `VersionProbeListener`
- [x] **PQCCallback.java** - Main orchestrator (renamed from ScannerMotherCallback)
  - Constructor: `(IPAddress, Consumer<PQCScanResult>, PQCScanOptions, HTTPNIOSocket)`
  - `start()` registers PQCNIOScanner with NIOSocket
  - Phase 2 tasks tracked via `AtomicInteger pendingCount`
  - Zero blocking — completion triggers `userCallback.accept(result)`
- [x] **PQCCallbackTest.java** - Tests for PQCCallback

#### Modified Files
- [x] **PQCNIOScanner.java** - Simplified
  - Now uses `ScanCallback` instead of `Consumer<PQCScanResult>`
  - Removed: options, httpNIOSocket, revocationChecker, cipherEnumerator, protocolTester
  - Only does Phase 1 (TLS handshake), Phase 2 handled by PQCCallback
- [x] **NIORevocationChecker.java** - Pure callback-based
  - Removed all `CompletableFuture` methods (`checkRevocationAsync`, `checkOCSPAsync`, `checkCRLAsync`)
  - Only callback-based: `checkRevocation(cert, issuer, Consumer<RevocationResult>)`
- [x] **QDZChecker.java** - Uses PQCCallback
  - Replaced `PQCNIOScanner` with `PQCCallback`
- [x] **PQCScannerTest.java** - Adapted tests
  - Uses `PQCCallback` for NIO scanner tests
  - Helper method tests use static `PQCNIOScanner.parseKeyExchangeType()` etc.

#### Architecture
```
User creates PQCCallback
         │
         ▼
    PQCCallback.start()
         │
         ▼ registers
    PQCNIOScanner (Phase 1: TLS Handshake)
         │
         ▼ calls
    ScanCallback.onHandshakeComplete()
         │
         ├─► NIORevocationChecker.checkRevocation() ──► callback
         ├─► CipherProbeCallback chain ──────────────► callback
         └─► VersionProbeCallback (parallel) ────────► callback
                                                          │
                                                          ▼
                                        pendingCount.decrementAndGet() == 0
                                                          │
                                                          ▼
                                               userCallback.accept(result)
```

---

## Previous Completed Work (2026-02-02)

### Refactor: Eliminated NIOHttpClient in favor of HTTPURLCallback + HTTPNIOSocket

Replaced the fake-async `NIOHttpClient` (blocking selector loop wrapped in `CompletableFuture`) with
the framework-native `HTTPURLCallback` + `HTTPNIOSocket` for truly event-driven, multiplexed HTTP.

#### Changes
- [x] **NIORevocationChecker** - Rewritten to use `HTTPNIOSocket` + `HTTPURLCallback`
  - Constructor takes `HTTPNIOSocket` instead of `int timeoutMs`
  - CRL downloads via `HTTPURLCallback` GET
  - OCSP requests via `HTTPURLCallback` POST with `HTTPMessageConfig.buildHMCI()`
  - No more thread-per-request blocking; multiplexed on shared NIO selector
- [x] **QDZChecker** - Uses `NIOHTTPServer.getHTTPNIOSocket()` to get shared `HTTPNIOSocket`
- [x] **NIOHTTPServer** - Added `getHTTPNIOSocket()` accessor; creates `HTTPNIOSocket` during `start()`
- [x] **NIOHttpClient.java** - DELETED (replaced entirely)

---

### Phase 2 Features - COMPLETED (2026-01-31)

#### Feature 1: CRL/OCSP Revocation Checking
- [x] **OPSecUtil.extractCRLDistributionPoints()** - Extract CRL URLs from certificate
- [x] **OPSecUtil.extractOCSPResponderURLs()** - Extract OCSP URLs from certificate
- [x] **OPSecUtil.extractCAIssuerURLs()** - Extract CA Issuer URLs from AIA extension
- [x] **OPSecUtil.checkCRL()** - Check certificate against CRL
- [x] **OPSecUtil.checkOCSP()** - Check certificate via OCSP responder
- [x] **OPSecUtil.checkRevocation()** - Combined check (OCSP first, CRL fallback)
- [x] **RevocationStatus enum** - GOOD, REVOKED, UNKNOWN, ERROR
- [x] **RevocationResult class** - Full result with method, date, reason
- [x] **PQCScanResult** - Added revocationMethod, revocationError, revocationDate, revocationReason fields

#### Feature 2: Cipher Suite Enumeration
- [x] **CipherSuiteEnumerator.java** - New class for cipher enumeration
  - Iterative enumeration algorithm (connect, note selection, remove, repeat)
  - TLS 1.3 and TLS 1.2 cipher suite support
  - Weak and insecure cipher testing (optional)
  - Server cipher preference detection
- [x] **CipherInfo class** - Cipher details (name, strength, key exchange, forward secrecy)
- [x] **EnumerationResult class** - List of supported ciphers with server preference flag
- [x] **OPSecUtil.CipherStrength enum** - STRONG, ACCEPTABLE, WEAK, INSECURE, UNKNOWN
- [x] **OPSecUtil.CipherComponents class** - Parsed cipher suite components
- [x] **OPSecUtil.classifyCipherSuiteStrength()** - Strength classification
- [x] **OPSecUtil.parseCipherSuite()** - Parse cipher name to components
- [x] **PQCScanResult** - Added supportedCipherSuites, serverCipherPreference fields

#### Feature 3: Protocol Version Testing
- [x] **ProtocolVersionTester.java** - New class for version probing
  - Tests TLS 1.3, TLS 1.2, TLS 1.1, TLS 1.0, SSLv3
  - Individual version testing
  - Deprecated protocol detection
  - Security recommendations
- [x] **VersionTestResult class** - Supported versions with security analysis
- [x] **OPSecUtil.ProtocolSecurity enum** - SECURE, DEPRECATED, CRITICAL, UNKNOWN
- [x] **OPSecUtil.classifyProtocolVersionSecurity()** - Version security classification
- [x] **OPSecUtil.protocolSupportsPQC()** - Check if version supports PQC
- [x] **PQCScanResult** - Added supportedProtocolVersions, sslv3Supported, deprecatedProtocolsSupported

#### Feature 4: Scan Configuration
- [x] **PQCScanOptions.java** - Scan configuration builder
  - checkRevocation, revocationTimeoutMs
  - enumerateCiphers, includeWeakCiphers, includeInsecureCiphers
  - testProtocolVersions, testSSLv3, testTLS10, testTLS11
  - connectTimeoutMs, enumerationTimeoutMs
  - `PQCScanOptions.defaults()` and `PQCScanOptions.comprehensive()` factory methods

---

### PQC Scanner Core - COMPLETED (Phase 1)
- [x] **PQCNIOScanner** - Non-blocking TLS scanner with NIO integration
- [x] **PQCTlsClient** - BC TLS client advertising PQC hybrid algorithms (X25519MLKEM768, SecP256r1MLKEM768)
- [x] **PQCTlsClientProtocol** - Intercepts ServerHello key_share for PQC detection
- [x] **PQCSSLStateMachine** - State machine for async TLS handshake
- [x] **PQCScanResult** - Comprehensive result container
- [x] **QDZChecker** - REST endpoint `/check-qdz/{domain}/{port}/{timeout}`
- [x] **DNSRegistrar.resolve()** - Quick DNS resolution with caching

---

## Pending Issues / Next Steps

### Medium Priority
1. **Vulnerability Scanning Framework**
   - POODLE (SSLv3 padding oracle)
   - BEAST (TLS 1.0 CBC)
   - Heartbleed (OpenSSL)
   - ROBOT (RSA padding oracle)
   - SWEET32 (64-bit block ciphers)
   - DROWN (SSLv2)

2. **HTTP Security Headers Analysis**
   - HSTS, CSP, X-Frame-Options, X-Content-Type-Options
   - Cookie security (Secure, HttpOnly, SameSite)

3. **Grading Engine** - SSL Labs compatible A+ to F grading

### Lower Priority
4. **CNSA 2.0 Compliance Checking** - Timeline-based compliance rules
5. **HTML Report Generation** - Rich visual reports
6. **Additional REST API Endpoints** - Beyond QDZChecker
7. **Performance Optimization** - Connection pooling, caching
8. **Integration Tests** - Test new features against real servers

---

## Architectural Decisions (IMPORTANT)

### Utility Functions Location
**All reusable utility functions MUST be created in the `opsec` module**, specifically in:
```
opsec/src/main/java/io/xlogistx/opsec/OPSecUtil.java
```

### Cryptography Library
**Bouncy Castle** is the primary cryptographic library. Use it for:
- Certificate parsing and validation
- TLS/SSL operations
- Post-Quantum Cryptography (ML-KEM, ML-DSA)
- Key exchange analysis
- Signature verification
- OCSP/CRL checking

**Do NOT** introduce alternative crypto libraries (e.g., liboqs) - Bouncy Castle covers all PQC requirements.

### TLS Implementation Strategy
**Bouncy Castle TLS API for all scanning**

| Use Case | Implementation | Reason |
|----------|----------------|--------|
| TLS 1.2/1.3 basic handshake | BC TLS API | PQC support needed |
| Certificate chain retrieval | BC TLS API | Already integrated |
| SSL 2.0/3.0 testing | BC TLS API | Disabled in Java SSLEngine |
| PQC/Hybrid key exchange | BC TLS API | Experimental cipher suites |
| Cipher enumeration | BC TLS API | Full control over cipher list |
| Protocol version testing | BC TLS API | Individual version control |
| Vulnerability testing | BC TLS API + raw bytes | Malformed packet testing |

---

## Current Package Structure

```
io.xlogistx.nosneak/
├── nmap/                          # Network scanning (NMap-like)
│   ├── NMapScanner.java           # Main scan orchestrator
│   ├── NMap.java                  # CLI entry point
│   ├── config/                    # Scan configuration
│   ├── discovery/                 # Host discovery (ARP/TCP/ICMP)
│   ├── scan/tcp/                  # TCP Connect scan engine
│   ├── scan/udp/                  # UDP scan engine
│   ├── service/                   # Service detection
│   │   └── probes/                # Protocol probes (TLS, HTTP, SSH)
│   ├── output/                    # Report formatters (JSON, XML, CSV)
│   └── util/                      # Scan results, port states
│
├── scanners/                      # PQC-specific scanning (ACTIVE)
│   ├── PQCCallback.java           # **MAIN ENTRY POINT** - NIO callback orchestrator
│   ├── ScanCallback.java          # Interface between PQCNIOScanner and PQCCallback
│   ├── PQCNIOScanner.java         # Phase 1 TLS handshake scanner
│   ├── PQCScanResult.java         # Result container
│   ├── PQCScanOptions.java        # Scan configuration
│   ├── TLSProbeCallback.java      # Base class for NIO TLS probes
│   ├── CipherProbeCallback.java   # NIO cipher enumeration probe
│   ├── VersionProbeCallback.java  # NIO protocol version probe
│   ├── NIORevocationChecker.java  # Async CRL/OCSP via HTTPURLCallback (callback-based)
│   ├── CipherSuiteEnumerator.java # Cipher info classes (CipherInfo, etc.)
│   ├── ProtocolVersionTester.java # Version name utilities
│   ├── PQCSessionConfig.java      # TLS session state
│   ├── PQCSSLStateMachine.java    # Handshake state machine
│   ├── PQCTlsClient.java          # BC TLS client with PQC
│   ├── PQCTlsClientProtocol.java  # BC TLS protocol handler
│   └── PQCConnectionHelper.java   # State machine interface
│
└── services/
    └── QDZChecker.java            # REST endpoint for PQC scanning
```

---

## Key Files

### PQC Scanner
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/PQCCallback.java` - **MAIN ENTRY POINT**
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/ScanCallback.java` - Interface
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/PQCNIOScanner.java` - Phase 1 handshake
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/PQCScanResult.java`
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/PQCScanOptions.java`
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/TLSProbeCallback.java` - Base probe class
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/CipherProbeCallback.java` - Cipher probe
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/VersionProbeCallback.java` - Version probe
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/NIORevocationChecker.java` - Revocation (callback-based)
- `no-sneak/src/main/java/io/xlogistx/nosneak/scanners/PQCTlsClient.java`
- `no-sneak/src/main/java/io/xlogistx/nosneak/services/QDZChecker.java`

### OPSec Utilities
- `opsec/src/main/java/io/xlogistx/opsec/OPSecUtil.java` - Extended with:
  - CRL/OCSP extraction and checking
  - Cipher suite classification
  - Protocol version security

### Tests
- `no-sneak/src/test/java/io/xlogistx/nosneak/scanners/PQCCallbackTest.java` - Main scanner tests
- `no-sneak/src/test/java/io/xlogistx/nosneak/scanners/PQCScannerTest.java` - Handshake and helper tests

---

## API Response Format (PQCScanResult.toNVGenericMap)

```json
{
  "host": "google.com",
  "port": 443,
  "scan-id": "uuid",
  "scan-time-in-ms": 150,
  "success": true,
  "secure": true,
  "tls-version": "TLSv1.3",
  "tls-version-pqc-capable": true,
  "key-exchange-type": "PQC_HYBRID",
  "key-exchange-algorithm": "X25519MLKEM768",
  "key-exchange-pqc-ready": true,
  "cipher-suite": "TLS_AES_256_GCM_SHA384",
  "cert-signature-type": "ECDSA",
  "cert-signature-algorithm": "SHA256withECDSA",
  "cert-public-key-type": "ECDSA",
  "cert-public-key-size": 256,
  "cert-pqc-ready": false,
  "cert-not-before": "2026-01-12 08:36:50.000 GMT",
  "cert-not-after": "2026-04-06 08:36:49.000 GMT",
  "cert-time-valid": true,
  "cert-chain-valid": true,
  "cert-revoked": false,
  "cert-subject": "CN=*.google.com",
  "cert-issuer": "CN=WE2,O=Google Trust Services,C=US",
  "revocation-method": "OCSP",
  "supported-cipher-suites": [
    {"name": "TLS_AES_256_GCM_SHA384", "strength": "STRONG", "forward-secrecy": true},
    {"name": "TLS_CHACHA20_POLY1305_SHA256", "strength": "STRONG", "forward-secrecy": true}
  ],
  "server-cipher-preference": true,
  "supported-protocol-versions": ["TLSv1.3", "TLSv1.2"],
  "sslv3-supported": false,
  "deprecated-protocols-supported": false,
  "overall-status": "READY",
  "recommendations": {
    "upgrade-to-pqc-certificate": "Consider migrating to PQC certificates (ML-DSA) for full quantum resistance"
  }
}
```

---

## Progress Tracking

- [x] **Sprint 1: PQC Scanner Foundation** - COMPLETE
  - [x] PQCNIOScanner with state machine
  - [x] PQCScanResult with all fields
  - [x] BC TLS client with PQC support
  - [x] Certificate chain verification
  - [x] REST endpoint (QDZChecker)
  - [x] DNS resolution integration

- [x] **Sprint 2: Certificate Deep Analysis** - COMPLETE
  - [x] OCSP checking
  - [x] CRL checking
  - [x] RevocationResult with status, method, date, reason

- [x] **Sprint 3: Protocol & Cipher Enumeration** - COMPLETE
  - [x] Protocol version testing (all versions)
  - [x] Full cipher suite enumeration
  - [x] Server cipher preference detection
  - [x] PQCScanOptions configuration

- [x] **Sprint 3.5: Pure NIO Callback Architecture** - COMPLETE (2026-02-04)
  - [x] PQCCallback orchestrator (replaces CompletableFuture)
  - [x] ScanCallback interface
  - [x] TLSProbeCallback base class
  - [x] CipherProbeCallback (NIO cipher enumeration)
  - [x] VersionProbeCallback (NIO version testing)
  - [x] NIORevocationChecker (callback-based, no CompletableFuture)
  - [x] PQCNIOScanner simplified (Phase 1 only)
  - [x] QDZChecker updated to use PQCCallback
  - [x] Zero blocking/waiting - pure event-driven

- [ ] **Sprint 4: Vulnerability Scanning**
  - [ ] POODLE, BEAST, Heartbleed, ROBOT
  - [ ] Weak cipher detection
  - [ ] Certificate vulnerabilities

- [ ] **Sprint 5: Grading & Compliance**
  - [ ] SSL Labs compatible grading
  - [ ] CNSA 2.0 compliance
  - [ ] PCI DSS / NIST rules

- [ ] **Sprint 6: Reporting & API**
  - [ ] HTML reports
  - [ ] Extended REST API
  - [ ] Performance optimization

---

## Usage Examples

### Basic PQC Scan (Recommended - using PQCCallback)
```java
HTTPNIOSocket httpNIOSocket = new HTTPNIOSocket(nioSocket);
IPAddress address = new IPAddress("google.com", 443);

PQCCallback scanner = new PQCCallback(address, result -> {
    System.out.println("Status: " + result.getOverallStatus());
    System.out.println("TLS: " + result.getTlsVersion());
    System.out.println("Key Exchange: " + result.getKeyExchangeAlgorithm());
}, null, httpNIOSocket);

scanner.dnsResolver(DNSRegistrar.SINGLETON);
scanner.timeoutInSec(10);
scanner.start();  // Non-blocking, callback fires when complete
```

### Comprehensive Scan with Options
```java
PQCScanOptions options = PQCScanOptions.builder()
    .checkRevocation(true)
    .revocationTimeoutMs(5000)
    .enumerateCiphers(true)
    .includeWeakCiphers(true)
    .testProtocolVersions(true)
    .testTLS10(true)
    .testTLS11(true)
    .testSSLv3(false)
    .build();

PQCCallback scanner = new PQCCallback(address, result -> {
    // All Phase 2 results included
    System.out.println("Ciphers: " + result.getSupportedCipherSuites());
    System.out.println("Versions: " + result.getSupportedProtocolVersions());
    System.out.println("Revoked: " + result.isCertRevoked());
}, options, httpNIOSocket);

scanner.dnsResolver(DNSRegistrar.SINGLETON);
scanner.timeoutInSec(30);
scanner.start();
```

### Callback-based Revocation Checking
```java
NIORevocationChecker checker = new NIORevocationChecker(httpNIOSocket);
checker.checkRevocation(cert, issuerCert, result -> {
    System.out.println("Status: " + result.getStatus());
    System.out.println("Method: " + result.getMethod());
});
```

### Blocking Revocation Checking (OPSecUtil)
```java
OPSecUtil opsec = OPSecUtil.singleton();
RevocationResult result = opsec.checkRevocation(cert, issuerCert, 5000);
System.out.println("Status: " + result.getStatus());
System.out.println("Method: " + result.getMethod());
```

---

## Notes

- Full requirements document is in `README.md`
- This scanner differentiates NoSneak by offering PQC readiness assessment
- Focus on CNSA 2.0 timeline compliance as key selling point
- **All new utility functions go in `opsec/OPSecUtil.java`** - no exceptions
- **Bouncy Castle only** for all cryptographic operations
