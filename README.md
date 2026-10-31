# io-xlogistx

io-xlogistx is a multi-module Maven project of pure Java libraries and desktop
applications. It covers security and PKI, NIO networking, an embedded HTTPS server,
Apache Shiro integration, Swing components (including a PDF viewer), and two
standalone editors: one for hex and one for PDF.

All code is under the `io.xlogistx` package. The modules build on the
zoxweb core libraries (`org.zoxweb:zoxweb-core`), and all cryptography uses
Bouncy Castle.

## Modules

| Module | Artifact | Description |
|--------|----------|-------------|
| [`core`](core) | `xlogistx-core` | Core shared types, utilities and a client API (`XXClientAPI`) |
| [`common`](common) | `xlogistx-common` | HTTP protocol handling, NIO networking, DNS resolution with caching (dnsjava), SMTP mail, cron scheduler, crypto helpers, YAML/XML, text-to-image |
| [`http`](http) | `xlogistx-http` | NIO HTTP/1.1 and HTTPS server with annotation-mapped endpoints and WebSocket support (`NIOHTTPServer`) |
| [`shiro`](shiro) | `xlogistx-shiro` | Apache Shiro integration: realms, sessions, caching, authorization, and a datastore-backed `DomainSecurityManager` (`io.xlogistx.shiro.ds`) |
| [`opsec`](opsec) | `xlogistx-opsec` | PKI and crypto: X.509 certificates, CSR and PEM generation, certificate signing, CRL reading, chain validation, PQC (ML-KEM, ML-DSA), SSL identity and key managers, OpenVPN helpers, SSH, `SecretStore` (a BCFKS secrets vault) and the security admin CLI |
| [`gui-audio`](gui-audio) | `xlogistx-gui-audio` | Reusable Swing widgets, SVG icons, a Markdown viewer and editor, Markdown → PDF (`MDToPDF`), a pure-Java Mermaid renderer, a PDFBox viewer (`PDFViewerPanel`, `PDFViewerApp`), and audio recording |
| [`apps`](apps) | `apps` | Standalone desktop applications: a **hex editor** and a **PDF editor** |

Module dependencies: `common` uses `core`; `opsec` uses `core`, `common` and `shiro`; `http` uses all four; `gui-audio` uses `core` and `common`; `apps` uses `gui-audio`.

## Highlights

### Security and PKI (`opsec`)
- `OPSecUtil` collects the certificate, TLS and cryptography utilities: PKIX chain validation against the JDK trust store, RFC 6125 hostname matching, and post-quantum algorithm support.
- `SecretStore` is a single-password BCFKS vault. It holds text secrets (for example database credentials), AES master keys, and ML-DSA / ML-KEM key pairs with their certificates. It can be used from code or from the command line.
- `SecurityAdminTool` is an admin CLI. It seeds the permission catalog, bootstraps the super admin, and manages subjects, role grants, apps and registrar keys.

### Networking and HTTP (`common`, `http`)
- HTTP protocol handling, keep-alive tracking and endpoint mapping on top of zoxweb's event-driven NIO sockets.
- An HTTPS server built on NIO, with keep-alive handling, endpoints mapped by annotation, and WebSockets.
- DNS resolution with caching (`DNSRegistrar`).

### Desktop (`gui-audio`, `apps`)
- **PDF viewer**: lazy background rendering, zoom and fit modes, text search, text selection and copy, clickable links, save and print.
- **PDF editor** (`io.xlogistx.editor.pdf`, entry point `PDFMain`):
  - Page operations: insert, delete, rotate and reorder pages, with undo.
  - Text: rewrite existing page text in place, and fill AcroForm fields.
  - Annotations: highlight, underline, strikeout, notes, ink, shapes, lines, text boxes with embedded fonts, and image stamps.
  - Editing: cut, copy and paste of annotations, a thumbnail sidebar, several documents in tabs, and a built-in user guide (F1).
- **Hex editor** (`io.xlogistx.editor.hex`).
- **Markdown → PDF** (`MDToPDF`) with embedded fonts and Mermaid diagrams rendered to images. Command line: `md=... pdf=... css=...`.

## Building

Requirements: a JDK and Maven. The parent POM `io.xlogistx:xlogistx-mvn` and the
zoxweb dependencies must be available in your local or remote Maven repository.

```bash
# Build everything
mvn clean install

# Build one module and the modules it depends on
mvn clean install -pl opsec -am

# Run the tests
mvn test
mvn test -pl gui-audio -Dtest=PDFViewerPanelTest
```

## Running the desktop apps

```bash
# PDF viewer (gui-audio)
java -cp <classpath> io.xlogistx.gui.pdf.PDFViewerApp [file.pdf | file.md]

# PDF editor (apps)
java -cp <classpath> io.xlogistx.editor.pdf.PDFMain [file.pdf]
```

For more detail, see the per-module notes: [`apps/CLAUDE.md`](apps/CLAUDE.md),
[`gui-audio/CLAUDE.md`](gui-audio/CLAUDE.md) and the PDF editor design in
[`gui-audio/PDF-EDIT-DESIGN.md`](gui-audio/PDF-EDIT-DESIGN.md).

## License

See [LICENSE](LICENSE).
