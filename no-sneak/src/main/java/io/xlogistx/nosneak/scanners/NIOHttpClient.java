package io.xlogistx.nosneak.scanners;

import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Simple NIO-based HTTP client for CRL downloads and OCSP requests.
 * Uses non-blocking I/O with CompletableFuture for async results.
 */
public class NIOHttpClient {

    public static final LogWrapper log = new LogWrapper(NIOHttpClient.class).setEnabled(false);

    private static final int DEFAULT_HTTP_PORT = 80;
    private static final int DEFAULT_BUFFER_SIZE = 16384;

    private final ExecutorService executor;
    private final int timeoutMs;

    public NIOHttpClient(int timeoutMs) {
        this.timeoutMs = timeoutMs;
        this.executor = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "NIOHttpClient-worker");
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * HTTP response container
     */
    public static class HttpResponse {
        private final int statusCode;
        private final byte[] body;
        private final String errorMessage;

        public HttpResponse(int statusCode, byte[] body) {
            this.statusCode = statusCode;
            this.body = body;
            this.errorMessage = null;
        }

        public HttpResponse(String errorMessage) {
            this.statusCode = -1;
            this.body = null;
            this.errorMessage = errorMessage;
        }

        public int getStatusCode() { return statusCode; }
        public byte[] getBody() { return body; }
        public String getErrorMessage() { return errorMessage; }
        public boolean isSuccess() { return statusCode >= 200 && statusCode < 300; }
        public boolean isError() { return errorMessage != null; }
    }

    /**
     * Perform async HTTP GET request.
     *
     * @param url the URL to fetch
     * @return CompletableFuture with the response
     */
    public CompletableFuture<HttpResponse> get(String url) {
        return CompletableFuture.supplyAsync(() -> doGet(url), executor);
    }

    /**
     * Perform async HTTP POST request.
     *
     * @param url the URL to post to
     * @param contentType the content type header
     * @param body the request body
     * @return CompletableFuture with the response
     */
    public CompletableFuture<HttpResponse> post(String url, String contentType, byte[] body) {
        return CompletableFuture.supplyAsync(() -> doPost(url, contentType, body), executor);
    }

    private HttpResponse doGet(String url) {
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            int port = uri.getPort() > 0 ? uri.getPort() : DEFAULT_HTTP_PORT;
            String path = uri.getRawPath();
            if (path == null || path.isEmpty()) path = "/";
            if (uri.getRawQuery() != null) path += "?" + uri.getRawQuery();

            String request = "GET " + path + " HTTP/1.1\r\n" +
                    "Host: " + host + "\r\n" +
                    "Connection: close\r\n" +
                    "Accept: */*\r\n" +
                    "\r\n";

            return executeRequest(host, port, request.getBytes(StandardCharsets.US_ASCII));
        } catch (Exception e) {
            return new HttpResponse("GET failed: " + e.getMessage());
        }
    }

    private HttpResponse doPost(String url, String contentType, byte[] body) {
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            int port = uri.getPort() > 0 ? uri.getPort() : DEFAULT_HTTP_PORT;
            String path = uri.getRawPath();
            if (path == null || path.isEmpty()) path = "/";

            String headers = "POST " + path + " HTTP/1.1\r\n" +
                    "Host: " + host + "\r\n" +
                    "Content-Type: " + contentType + "\r\n" +
                    "Content-Length: " + body.length + "\r\n" +
                    "Connection: close\r\n" +
                    "\r\n";

            byte[] headerBytes = headers.getBytes(StandardCharsets.US_ASCII);
            byte[] request = new byte[headerBytes.length + body.length];
            System.arraycopy(headerBytes, 0, request, 0, headerBytes.length);
            System.arraycopy(body, 0, request, headerBytes.length, body.length);

            return executeRequest(host, port, request);
        } catch (Exception e) {
            return new HttpResponse("POST failed: " + e.getMessage());
        }
    }

    private HttpResponse executeRequest(String host, int port, byte[] request) {
        SocketChannel channel = null;
        Selector selector = null;

        try {
            channel = SocketChannel.open();
            channel.configureBlocking(false);
            channel.connect(new InetSocketAddress(host, port));

            selector = Selector.open();
            channel.register(selector, SelectionKey.OP_CONNECT);

            long deadline = System.currentTimeMillis() + timeoutMs;
            ByteBuffer writeBuffer = ByteBuffer.wrap(request);
            ByteArrayOutputStream responseBuffer = new ByteArrayOutputStream();
            ByteBuffer readBuffer = ByteBuffer.allocate(DEFAULT_BUFFER_SIZE);

            boolean connected = false;
            boolean requestSent = false;

            while (System.currentTimeMillis() < deadline) {
                long remaining = deadline - System.currentTimeMillis();
                if (remaining <= 0) break;

                int ready = selector.select(Math.min(remaining, 1000));
                if (ready == 0) continue;

                Iterator<SelectionKey> keys = selector.selectedKeys().iterator();
                while (keys.hasNext()) {
                    SelectionKey key = keys.next();
                    keys.remove();

                    if (key.isConnectable()) {
                        if (channel.finishConnect()) {
                            connected = true;
                            key.interestOps(SelectionKey.OP_WRITE);
                        }
                    }

                    if (key.isWritable() && connected && !requestSent) {
                        channel.write(writeBuffer);
                        if (!writeBuffer.hasRemaining()) {
                            requestSent = true;
                            key.interestOps(SelectionKey.OP_READ);
                        }
                    }

                    if (key.isReadable() && requestSent) {
                        readBuffer.clear();
                        int bytesRead = channel.read(readBuffer);
                        if (bytesRead == -1) {
                            // Connection closed - we have the full response
                            return parseResponse(responseBuffer.toByteArray());
                        }
                        if (bytesRead > 0) {
                            readBuffer.flip();
                            byte[] data = new byte[readBuffer.remaining()];
                            readBuffer.get(data);
                            responseBuffer.write(data);
                        }
                    }
                }
            }

            // Timeout - return what we have
            if (responseBuffer.size() > 0) {
                return parseResponse(responseBuffer.toByteArray());
            }
            return new HttpResponse("Request timeout");

        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("HTTP request failed: " + e.getMessage());
            }
            return new HttpResponse("Request failed: " + e.getMessage());
        } finally {
            IOUtil.close(selector, channel);
        }
    }

    private HttpResponse parseResponse(byte[] data) {
        try {
            String response = new String(data, StandardCharsets.ISO_8859_1);

            // Find end of headers
            int headerEnd = response.indexOf("\r\n\r\n");
            if (headerEnd == -1) {
                return new HttpResponse("Invalid HTTP response");
            }

            String headers = response.substring(0, headerEnd);
            String[] headerLines = headers.split("\r\n");

            // Parse status line
            if (headerLines.length == 0) {
                return new HttpResponse("Invalid HTTP response");
            }

            String statusLine = headerLines[0];
            String[] statusParts = statusLine.split(" ", 3);
            if (statusParts.length < 2) {
                return new HttpResponse("Invalid status line");
            }

            int statusCode = Integer.parseInt(statusParts[1]);

            // Extract body
            int bodyStart = headerEnd + 4;
            byte[] body = new byte[data.length - bodyStart];
            System.arraycopy(data, bodyStart, body, 0, body.length);

            return new HttpResponse(statusCode, body);
        } catch (Exception e) {
            return new HttpResponse("Failed to parse response: " + e.getMessage());
        }
    }

    /**
     * Shutdown the HTTP client executor.
     */
    public void shutdown() {
        executor.shutdown();
        try {
            executor.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
        }
    }
}
