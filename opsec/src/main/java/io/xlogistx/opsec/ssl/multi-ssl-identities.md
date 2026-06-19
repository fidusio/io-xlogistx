# Multi-Certificate SSL Identity Layer — Alias-Free, SNI-Routed, Hot-Reloadable, PQC-Ready

A TLS server-certificate layer that serves **multiple certificates on one IP / one port (443)**, selecting the right one per connection by **SNI**, so every hostname gets a **valid, trusted, error-free** TLS 1.2 / 1.3 session.

**Location:** package `io.xlogistx.opsec.ssl` in the `opsec` module. Certificate-name extraction and PEM reading are centralized in `io.xlogistx.opsec.OPSecUtil` (per the project rule that utilities live in `OPSecUtil`); BouncyCastle is used for the PKCS#1/SEC1/encrypted/PQC key formats the stock JDK 8 readers can't parse.

## What it does

- **One listener, many hostnames** — `*.xlogistx.io` (EC), `backend.zoxweb.com` (RSA), etc., each presenting its own correct certificate. The client's SNI hostname is matched against each certificate's **SAN dNSName / CN**, so no client sees a name-mismatch or untrusted warning.
- **Single-certificate shortcut** — if only one identity is loaded, it is served for **every** connection regardless of SNI (or its absence). Matching is skipped entirely.
- **No alias management** — identities are matched by the certificate's own names; the only token at the `KeyManager` SPI boundary is a SHA-256 fingerprint of the leaf cert.
- **Loads from anything** — existing keystores (`.p12`/`.jks`) *and* PEM identities (cert + key + chain), merged in-memory at `reload()`. No offline `keytool` merge.
- **App-driven hot reload** — when the application has a renewed cert it calls `reload()`; new handshakes use it immediately with **no restart**, in-flight handshakes drain on the old set (atomic swap under a `ReentrantReadWriteLock`).
- **Validity enforced on load** — an expired or not-yet-valid leaf aborts the reload (throws `CertificateValidityException`) and leaves the previously-serving certs live.
- **PEM via BouncyCastle** — PKCS#1, SEC1, PKCS#8, and **encrypted** private keys (`OPSecUtil.readPrivateKey` / `readCertificates`).
- **PQC-ready, signature-algorithm-aware selection** — a single hostname can be backed by **both** a classical (RSA/EC) and a post-quantum (ML-DSA/SLH-DSA/Falcon) certificate. PQC-capable clients (those advertising a PQC signature scheme) get the PQC cert; everyone else gets the classical one — no negotiation failure for clients that can't verify PQC.

## Why this shape (one IP, many names, all valid)

SNI travels in the ClientHello **before** the certificate is chosen, in both TLS 1.2 and 1.3, so one socket can answer many names. "Valid and error-free" requires four things, all covered: the **correct cert per name** (SNI→SAN/CN routing), the **full chain** sent (loader keeps leaf + intermediates), the cert **within its validity window** (validity-on-load + `expiresWithin()`/`reload()`), and the **right key type** for the negotiated handshake (RSA/EC/PQC coexist; selection is signature-algorithm-aware). Clients that send no SNI get the configured **default identity**; if only one cert is loaded, that one cert is served unconditionally.

## Classes

| Class | Responsibility |
|-------|----------------|
| `Identity` | Immutable `{key, chain[], names, token}`. `token` = SHA-256 of the leaf DER. `matches(host)` does RFC-6125 single-label wildcard matching (`*.foo.com` ⇒ `a.foo.com` + apex, not `a.b.foo.com`). `keyClass()` → `PQC` / `CLASSICAL` / `UNKNOWN`. Names cover **all** hostnames the cert carries — every SAN dNSName (`OPSecUtil.extractDNSNames`) plus every Subject CN (`OPSecUtil.extractCNs`). |
| `IdentityStore` | Loads identities from keystore + PEM sources, validity-checks on `reload()`, swaps the identity list + token map atomically under a write lock. Builds the `SSLContext` and exposes expiry helpers. |
| `IdentityKeyManager` | Alias-free `X509ExtendedKeyManager`. Routes each handshake to a cert by SNI; when multiple identities cover one host, selects by the client's advertised signature algorithms (PQC vs classical). |
| `DomainIdentityMatcher` | Indexed host → identity resolver backing `IdentityStore.resolve`/`resolveAll`: O(1) exact-name `HashMap` + small wildcard pass, same single-label semantics as `Identity.matches()`, load-order-preserving and de-duplicated. Immutable; rebuilt and swapped in `reload()`. |
| `CertificateValidityException` | Thrown by `reload()` for an expired / not-yet-valid leaf; the live identity set is left untouched. |

Supporting helpers in `OPSecUtil`: `extractDNSNames(cert)`, `extractCNs(cert)` / `extractCN(cert)`, `readCertificates(File)`, `readPrivateKey(File, char[])`.

## Dependencies

BouncyCastle (`bcprov-jdk18on` + `bcpkix-jdk18on`, project uses 1.84) for PEM/PKCS#1/encrypted/PQC key parsing. The **BC + BCJSSE + BCPQC** providers auto-install via `OPSecUtil.loadProviders()`. `SSLContext`, `SSLEngine`, the SNI classes, and `X509ExtendedKeyManager` are stock JDK 8 (TLS 1.3 needs 8u261+; on JDK 25 both 1.2/1.3 are present). The classes are JDK 8 source-compatible (no records/var/pattern-`instanceof`/`HexFormat`/`List.copyOf`).

> `IdentityStore.newSSLContext()` builds the context from the **BCJSSE** provider when available (falling back to the platform default), because stock SunJSSE on JDK 8 offers neither TLS 1.3 nor PQC signature schemes.

## Integration

```java
import io.xlogistx.opsec.ssl.IdentityStore;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.nio.file.Paths;

IdentityStore store = new IdentityStore("backend.zoxweb.com") // default when SNI absent/unmatched
        .setValidateValidity(true)        // reject expired / not-yet-valid leaf on load (default true)
        .setClockSkewMillis(60_000)       // optional clock-skew tolerance
        .setPreferPqc(true)               // serve PQC to capable clients when a PQC cert is present (default true)
        .addKeyStore(Paths.get("/var/mgw.xlogistx/wildcard.p12"), "PKCS12", wildcardPass)
        .addPem(Paths.get(".../backend.crt"), Paths.get(".../backend.key"),
                Paths.get(".../backend-chain.pem"), keyPassphrase /* null if unencrypted */);

store.reload();
SSLContext ctx = store.newSSLContext();   // BCJSSE-backed

SSLEngine engine = ctx.createSSLEngine();
engine.setUseClientMode(false);
engine.setEnabledProtocols(new String[]{ "TLSv1.3", "TLSv1.2" });
// For TLS 1.2 with mixed RSA+EC certs, keep both ECDHE_RSA and ECDHE_ECDSA cipher
// families enabled so either cert type can be served.
```

If you build the `SSLContext` yourself instead of calling `newSSLContext()`, wire `store.keyManager()` in as the `KeyManager` to keep the SNI routing.

### Single certificate

If the store holds exactly one identity, the KeyManager serves it for every connection and skips SNI matching — a single-cert deployment "just works" with no default-host configuration.

### Serving classical + PQC for the same host

```java
store.addPem(backendRsaCrt,   backendRsaKey,   backendRsaChain);   // RSA, classical
store.addPem(backendMldsaCrt, backendMldsaKey, backendMldsaChain); // ML-DSA, PQC
store.reload();
```

With `setPreferPqc(true)` (default), a client advertising an ML-DSA signature scheme is served the PQC cert; a client that isn't gets the RSA cert. Both cover the host, both are valid, neither client sees an error. Roll PQC out live by adding the PQC identity and `reload()`.

### Expiry / hot reload

```java
if (store.expiresWithin(30L*24*60*60*1000)) {   // ~30 days
    // ... app logic writes the renewed cert files ...
    try { store.reload(); }                      // new handshakes use it immediately, no restart
    catch (Exception e) { /* old certs still serving — log/alert */ }
}
```

- `store.expiresWithin(millisFromNow)` — poll from your scheduler to decide when to renew.
- `store.earliestExpiryMillis()` — soonest `notAfter` across loaded certs.

> Validity is checked at **load** time, not continuously: a cert that expires while loaded keeps being served until the next `reload()`. Poll `expiresWithin()` and reload ahead of expiry.

## Selection order

0. **One identity total** → serve it unconditionally (no SNI matching).
1. SNI matches multiple identities and the client advertises PQC (and `preferPqc`) → PQC identity.
2. Else the first **classical** identity the client can verify (by advertised signature algorithms).
3. Else any classical match.
4. Else the first match.
5. No SNI match at all → configured **default identity**.

Single-match hosts skip selection. Wildcard `*.xlogistx.io` matches one label deep plus the apex; exact names match exactly; all case-insensitive.

## Testing

`opsec/src/test/java/io/xlogistx/opsec/ssl/IdentityStoreTest.java` drives the layer end-to-end over a real in-memory `SSLEngine` TLS 1.2 handshake (BCJSSE), with self-generated EC, RSA, and ML-DSA certs:

- single-certificate shortcut (served regardless of SNI),
- SNI routing selects the cert by hostname,
- same-host classical coexistence (`resolveAll` returns both, a covering cert is served),
- `reload()` rejects an expired leaf and keeps the previous identities,
- PEM source loading (`OPSecUtil.readCertificates` / `readPrivateKey`),
- PQC-vs-classical selection (PQC-capable client → PQC cert; classical-only → classical; `preferPqc=false` → classical).

`DomainIdentityMatcherTest.java` covers the resolver directly: exact (case-insensitive) lookup, single-label wildcard + apex (and the negatives `a.b.foo.com` / `xfoo.com`), multiple identities per host with load order, exact/wildcard de-duplication, and lowest-load-index `resolveFirst`.

`IdentityKeyManager.select(matches, peerSigAlgs)` is package-private as a test seam, since a real PQC TLS handshake is not yet negotiable on the JDK.

> Project note: Maven runs tests with `skipTests` by default, and the JUnit-Platform engine may be absent locally; run with `-DskipTests=false -Dmaven.test.skip=false`. The managed JUnit (6.x) requires JDK 17+ at test runtime even though the layer's source is JDK 8 compatible.

## Notes & caveats

- **SNI required for multiplexing.** With multiple certs, clients that send SNI (all modern TLS 1.2/1.3 clients) get the right cert by name; a client sending no SNI gets the configured default. With a single cert, SNI is irrelevant.
- **PQC auth depends on the platform.** Selection logic is ready now; loading and *signing* with an ML-DSA cert depends on the JDK/JSSE negotiating a PQC `signature_algorithms` value. `Identity.keyClass()` classifies by algorithm name (verified: BC 1.84 generates `ML-DSA-65/87` and the layer classifies them `PQC`).
- **PQC key exchange is separate.** Hybrid ML-KEM groups are negotiated by the TLS stack, not this cert layer — enable them at the `SSLParameters`/provider level independently.
- **Thread-safety.** Reads are lock-free off `volatile` references; `reload()` builds the new set then swaps under the write lock. The token map swaps together with the identity list, so `chooseEngineServerAlias` → `getPrivateKey` stays consistent across a concurrent reload.
- **Lookup cost.** Routing is **O(1)** for exact SNI names plus a small linear pass over wildcard certs, via `DomainIdentityMatcher` (built in `reload()`, swapped under the write lock with the identity list). It keeps an exact-name `HashMap<String,List<Identity>>` and a separate wildcard list using the same strict single-label semantics as `Identity.matches()`; results are de-duplicated and returned in load order, so selection is identical to the original linear scan. Only DNS names / CN are indexed — IP-literal SNI falls through to the default identity.
