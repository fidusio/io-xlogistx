package io.xlogistx.http;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.security.HashUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.http.HTTPServerConfig;
import org.zoxweb.shared.util.SharedStringUtil;

import java.io.*;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Proves the mid-transfer reset behavior of the finally block in NIOHTTPServer.incomingData()
 * when hph.canClose() is used as the teardown gate.
 *
 * Both tests upload the same payload to the same authenticated endpoint (HTTPUploadHandler,
 * requires system:upload:files) using valid BASIC credentials, sent in small slices with
 * pauses so the server receives multiple read events (partial dispatch).
 *
 * - chunkedUploadSucceeds: Transfer-Encoding chunked. securityCheck() installs the
 *   ShiroSession guard (canClose == isRequestComplete), so no mid-transfer reset. Expected PASS.
 * - contentLengthUploadSucceeds: Content-Length + application/octet-stream. canProceedAsPartial()
 *   is true but NO connection session is created (creation is gated on isTransferChunked),
 *   so hph.canClose() returns true after the first partial dispatch and the finally block
 *   resets the parser while the body is still arriving. Expected FAIL on current code.
 */
public class UploadPartialResetTest {

    private static final int PORT = 28087;
    private static final String USER = "uploader";
    private static final String PASSWORD = "Upl0ad!Test#2026";
    private static final int SLICE_SIZE = 64 * 1024;
    private static final int SLICE_COUNT = 16; // 1 MB total
    private static final long SLICE_DELAY_MS = 100;

    private static File storageDir;
    private static byte[] payload;
    private static String payloadSha256;

    @BeforeAll
    public static void startServer() throws Exception {
        File testRoot = new File("target/upload-partial-test").getAbsoluteFile();
        storageDir = new File(testRoot, "storage");
        storageDir.mkdirs();

        // self-contained credentials: generate the bcrypt hash at runtime
        String bcrypt = HashUtil.toBCryptPassword(PASSWORD, 10).getCanonicalID();

        File usersIni = new File(testRoot, "upload-test-users.ini");
        try (PrintWriter pw = new PrintWriter(usersIni, "UTF-8")) {
            pw.println("[users]");
            pw.println(USER + " = " + bcrypt + ", admin");
            pw.println("[roles]");
            pw.println("admin = *");
        }

        File shiroIni = new File(testRoot, "upload-test-shiro.ini");
        try (PrintWriter pw = new PrintWriter(shiroIni, "UTF-8")) {
            pw.println("[main]");
            pw.println("iniRealm = io.xlogistx.shiro.XlogistXIniRealm");
            pw.println("iniRealm.resourcePath = file:" + usersIni.getAbsolutePath().replace('\\', '/'));
            pw.println("iniRealm.name = upload-test-realm");
            pw.println("credentialsMatcher = io.xlogistx.shiro.authc.CredentialsInfoMatcher");
            pw.println("iniRealm.credentialsMatcher = $credentialsMatcher");
            pw.println("securityManager.realm = $iniRealm");
        }

        String configJSON = "{\n" +
                "  \"name\": \"upload-partial-test\",\n" +
                "  \"properties\": {\n" +
                "    \"shiro\": { \"config\": \"file:" + shiroIni.getAbsolutePath().replace('\\', '/') + "\" },\n" +
                "    \"keep-alive\": { \"time_out\": \"30s\", \"maximum\": 1000 }\n" +
                "  },\n" +
                "  \"connections\": [\n" +
                "    { \"name\": \"http\", \"schemes\": [\"http\"], \"socket_config\": { \"port\": " + PORT + ", \"backlog\": 64 } }\n" +
                "  ],\n" +
                "  \"endpoints\": [\n" +
                "    { \"bean\": \"io.xlogistx.http.services.HTTPUploadHandler\",\n" +
                "      \"properties\": { \"base_folder\": \"" + storageDir.getAbsolutePath().replace('\\', '/') + "\" } }\n" +
                "  ]\n" +
                "}";

        HTTPServerConfig config = GSONUtil.fromJSON(configJSON, HTTPServerConfig.class);
        NIOHTTPServer server = new NIOHTTPServer(config);
        server.start();

        // wait until the port accepts connections
        for (int i = 0; i < 50; i++) {
            try (Socket probe = new Socket("localhost", PORT)) {
                break;
            } catch (IOException e) {
                Thread.sleep(100);
            }
        }

        payload = new byte[SLICE_SIZE * SLICE_COUNT];
        new Random(0xF00D).nextBytes(payload);
        payloadSha256 = sha256Hex(payload);
    }

    @Test
    public void chunkedUploadSucceeds() throws Exception {
        String response = upload("chunked-upload.bin", true);
        assertUploadOK(response, "chunked-upload.bin");
    }

    @Test
    public void contentLengthUploadSucceeds() throws Exception {
        String response = upload("content-length-upload.bin", false);
        assertUploadOK(response, "content-length-upload.bin");
    }

    private static void assertUploadOK(String response, String filename) throws Exception {
        assertTrue(response.startsWith("HTTP/1.1 200"),
                "expected 200 OK, got:\n" + (response.isEmpty() ? "<no response / timeout>" : response));
        assertTrue(response.contains(payloadSha256),
                "response does not contain the expected sha-256 " + payloadSha256 + ":\n" + response);

        File stored = new File(storageDir, filename);
        assertTrue(stored.isFile(), "uploaded file missing: " + stored);
        byte[] storedBytes = Files.readAllBytes(stored.toPath());
        assertEquals(payload.length, storedBytes.length, "stored file size mismatch");
        assertEquals(payloadSha256, sha256Hex(storedBytes), "stored file content mismatch");
    }

    /**
     * Raw-socket upload so slices are flushed with pauses, forcing the server
     * to process the request across multiple NIO read events.
     */
    private static String upload(String filename, boolean chunked) throws Exception {
        try (Socket socket = new Socket("localhost", PORT)) {
            // generous timeout: the sessionless content-length path re-authenticates
            // (bcrypt) on every 4KB read event, ~18s total for 1MB
            socket.setSoTimeout(60000);
            socket.setTcpNoDelay(true);
            OutputStream os = socket.getOutputStream();

            String auth = Base64.getEncoder().encodeToString(
                    SharedStringUtil.getBytes(USER + ":" + PASSWORD));
            StringBuilder headers = new StringBuilder()
                    .append("POST /system-upload/").append(filename).append(" HTTP/1.1\r\n")
                    .append("Host: localhost:").append(PORT).append("\r\n")
                    .append("Authorization: Basic ").append(auth).append("\r\n")
                    .append("Content-Type: application/octet-stream\r\n");
            if (chunked)
                headers.append("Transfer-Encoding: chunked\r\n");
            else
                headers.append("Content-Length: ").append(payload.length).append("\r\n");
            headers.append("\r\n");

            os.write(headers.toString().getBytes(StandardCharsets.US_ASCII));
            os.flush();
            Thread.sleep(SLICE_DELAY_MS * 2); // headers land as their own read event

            try {
                for (int i = 0; i < SLICE_COUNT; i++) {
                    if (chunked) {
                        os.write((Integer.toHexString(SLICE_SIZE) + "\r\n").getBytes(StandardCharsets.US_ASCII));
                        os.write(payload, i * SLICE_SIZE, SLICE_SIZE);
                        os.write("\r\n".getBytes(StandardCharsets.US_ASCII));
                    } else {
                        os.write(payload, i * SLICE_SIZE, SLICE_SIZE);
                    }
                    os.flush();
                    Thread.sleep(SLICE_DELAY_MS);
                }
                if (chunked) {
                    os.write("0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
                    os.flush();
                }
            } catch (IOException e) {
                System.err.println("send aborted by server: " + e);
            }

            ByteArrayOutputStream response = new ByteArrayOutputStream();
            try {
                InputStream is = socket.getInputStream();
                byte[] buffer = new byte[8192];
                int read;
                while ((read = is.read(buffer)) != -1)
                    response.write(buffer, 0, read);
            } catch (SocketTimeoutException e) {
                System.err.println("read timed out after 15s with " + response.size() + " bytes received");
            } catch (IOException e) {
                System.err.println("read aborted: " + e);
            }
            return response.toString("UTF-8");
        }
    }

    private static String sha256Hex(byte[] data) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(data);
        StringBuilder sb = new StringBuilder(hash.length * 2);
        for (byte b : hash)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }

    // standalone runner: mvn in this environment cannot fetch the surefire junit-platform provider
    public static void main(String[] args) throws Exception {
        boolean debug = args.length > 0 && "debug".equals(args[0]);
        if (debug) {
            org.zoxweb.server.http.HTTPRawMessage.log.setEnabled(true);
            io.xlogistx.http.services.HTTPUploadHandler.log.setEnabled(true);
        }
        startServer();
        int failures = 0;
        UploadPartialResetTest test = new UploadPartialResetTest();
        String[] tests = debug ? new String[]{"contentLengthUploadSucceeds"}
                : new String[]{"chunkedUploadSucceeds", "contentLengthUploadSucceeds"};
        for (String name : tests) {
            System.out.println("\n=== " + name + " ===");
            try {
                UploadPartialResetTest.class.getMethod(name).invoke(test);
                System.out.println(">>> " + name + ": PASSED");
            } catch (java.lang.reflect.InvocationTargetException e) {
                failures++;
                System.out.println(">>> " + name + ": FAILED - " + e.getCause().getMessage());
            }
        }
        System.out.println("\n" + (failures == 0 ? "ALL PASSED" : failures + " test(s) FAILED"));
        System.exit(failures);
    }
}
