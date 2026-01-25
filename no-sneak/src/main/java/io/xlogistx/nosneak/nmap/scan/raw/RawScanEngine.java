package io.xlogistx.nosneak.nmap.scan.raw;

import io.xlogistx.nosneak.nmap.config.NMapConfig;
import io.xlogistx.nosneak.nmap.scan.*;
import io.xlogistx.nosneak.nmap.util.PortResult;
import io.xlogistx.nosneak.nmap.util.PortState;
import io.xlogistx.nosneak.nmap.util.ScanResult;
import io.xlogistx.nosneak.nmap.util.ScanType;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Abstract base class for scan engines.
 * Pure Java implementation using NIO non-blocking sockets.
 *
 * Note: True raw socket scans (SYN-only, FIN, NULL, Xmas) require OS-level
 * raw sockets which Java NIO doesn't support. This implementation uses
 * TCP connect behavior with timing heuristics to approximate results.
 */
public abstract class RawScanEngine implements ScanEngine {

    public static final LogWrapper log = new LogWrapper(RawScanEngine.class).setEnabled(false);


    protected NMapConfig config;
    protected ExecutorService executor;
    protected volatile AtomicBoolean closed = new AtomicBoolean(false);
    protected final AtomicInteger activeScans = new AtomicInteger(0);

    @Override
    public abstract ScanType getScanType();

    @Override
    public String getDescription() {
        return getScanType().getDescription() + " (Java NIO implementation)";
    }

    @Override
    public boolean isAvailable() {
        // Pure Java implementation is always available
        return true;
    }

    @Override
    public void init(ExecutorService executorService, NMapConfig config) {
        this.config = config;
        this.executor = executorService;
    }

    @Override
    public CompletableFuture<PortResult> scanPort(String host, int port) {
        return CompletableFuture.supplyAsync(() -> {
            activeScans.incrementAndGet();
            try {
                return performPortScan(host, port);
            } finally {
                activeScans.decrementAndGet();
            }
        }, executor);
    }

    @Override
    public CompletableFuture<ScanResult> scanHost(String host, List<Integer> ports) {
        long startTime = System.currentTimeMillis();

        // Scan ports with controlled parallelism
        List<CompletableFuture<PortResult>> futures = new ArrayList<>();

        for (int port : ports) {
            CompletableFuture<PortResult> future = scanPort(host, port);
            futures.add(future);

            // Rate limiting based on timing template
            long delay = config.getTiming().getProbeDelayMs();
            if (delay > 0) {
                try {
                    Thread.sleep(delay);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }

        // Wait for all futures and collect results without blocking
        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
            .thenApply(v -> {
                List<PortResult> results = new ArrayList<>();
                boolean hostUp = false;

                for (CompletableFuture<PortResult> future : futures) {
                    try {
                        // Use join() - futures are already complete after allOf()
                        PortResult result = future.join();
                        results.add(result);
                        if (result.isOpen() || result.isClosed()) {
                            hostUp = true;
                        }
                    } catch (Exception e) {
                        if (log.isEnabled()) {
                            log.getLogger().warning("Port scan failed: " + e.getMessage());
                        }
                    }
                }

                long endTime = System.currentTimeMillis();

                return ScanResult.builder(host)
                        .resolveAddress()
                        .hostUp(hostUp)
                        .hostUpReason(hostUp ? "tcp-response" : "no-response")
                        .startTime(startTime)
                        .endTime(endTime)
                        .portResults(results)
                        .build();
            });
    }

    /**
     * Perform a single port scan using NIO.
     * Subclasses can override to provide scan-type specific behavior.
     */
    protected PortResult performPortScan(String host, int port) {
        long startTime = System.currentTimeMillis();
        int timeoutMs = config.getTimeoutSec() * 1000;
        if (timeoutMs <= 0) {
            timeoutMs = 5000;
        }

        SocketChannel channel = null;
        Selector selector = null;

        try {
            channel = SocketChannel.open();
            channel.configureBlocking(false);
            selector = Selector.open();

            // Start connection
            InetSocketAddress address = new InetSocketAddress(host, port);
            boolean connected = channel.connect(address);

            if (!connected) {
                // Connection in progress, wait for completion
                channel.register(selector, SelectionKey.OP_CONNECT);

                int readyCount = selector.select(timeoutMs);

                if (readyCount == 0) {
                    // Timeout - port is filtered
                    long responseTime = System.currentTimeMillis() - startTime;
                    return createFilteredResult(port, responseTime);
                }

                Set<SelectionKey> keys = selector.selectedKeys();
                Iterator<SelectionKey> iter = keys.iterator();

                while (iter.hasNext()) {
                    SelectionKey key = iter.next();
                    iter.remove();

                    if (key.isConnectable()) {
                        try {
                            if (channel.finishConnect()) {
                                // Connection successful - port is open
                                long responseTime = System.currentTimeMillis() - startTime;
                                return createOpenResult(port, responseTime, channel);
                            }
                        } catch (IOException e) {
                            // Connection refused or reset - port is closed
                            long responseTime = System.currentTimeMillis() - startTime;
                            return createClosedResult(port, responseTime, e);
                        }
                    }
                }
            } else {
                // Immediate connection - port is open
                long responseTime = System.currentTimeMillis() - startTime;
                return createOpenResult(port, responseTime, channel);
            }

            // Fallback - shouldn't reach here normally
            long responseTime = System.currentTimeMillis() - startTime;
            return PortResult.builder(port, getScanType().getProtocol())
                    .state(PortState.UNKNOWN)
                    .reason("unknown")
                    .responseTime(responseTime)
                    .build();

        } catch (java.net.ConnectException e) {
            // Connection refused - port is closed
            long responseTime = System.currentTimeMillis() - startTime;
            return createClosedResult(port, responseTime, e);
        } catch (java.net.NoRouteToHostException e) {
            // No route - host is unreachable
            long responseTime = System.currentTimeMillis() - startTime;
            return PortResult.builder(port, getScanType().getProtocol())
                    .state(PortState.FILTERED)
                    .reason("no-route")
                    .responseTime(responseTime)
                    .build();
        } catch (SocketTimeoutException e) {
            // Timeout - port is filtered
            long responseTime = System.currentTimeMillis() - startTime;
            return createFilteredResult(port, responseTime);
        } catch (IOException e) {
            long responseTime = System.currentTimeMillis() - startTime;
            String reason = e.getMessage();

            // Analyze the exception to determine port state
            if (reason != null && reason.toLowerCase().contains("refused")) {
                return createClosedResult(port, responseTime, e);
            } else if (reason != null && reason.toLowerCase().contains("reset")) {
                return createClosedResult(port, responseTime, e);
            }

            return PortResult.builder(port, getScanType().getProtocol())
                    .state(PortState.FILTERED)
                    .reason("error: " + reason)
                    .responseTime(responseTime)
                    .build();
        } finally {
            IOUtil.close(selector, channel);
        }
    }

    /**
     * Create an OPEN port result. Subclasses can override for scan-specific behavior.
     */
    protected PortResult createOpenResult(int port, long responseTime, SocketChannel channel) {
        PortResult.Builder builder = PortResult.builder(port, getScanType().getProtocol())
                .state(PortState.OPEN)
                .reason(getOpenReason())
                .responseTime(responseTime);

        // Try to grab banner if service detection is enabled
        if (config.isServiceDetection()) {
            String banner = tryGrabBanner(channel);
            if (banner != null && !banner.isEmpty()) {
                builder.banner(banner);
            }
        }

        return builder.build();
    }

    /**
     * Create a CLOSED port result. Subclasses can override for scan-specific behavior.
     */
    protected PortResult createClosedResult(int port, long responseTime, Exception e) {
        String reason = getClosedReason();
        if (e != null && e.getMessage() != null) {
            if (e.getMessage().toLowerCase().contains("reset")) {
                reason = "reset";
            }
        }

        return PortResult.builder(port, getScanType().getProtocol())
                .state(PortState.CLOSED)
                .reason(reason)
                .responseTime(responseTime)
                .build();
    }

    /**
     * Create a FILTERED port result. Subclasses can override for scan-specific behavior.
     */
    protected PortResult createFilteredResult(int port, long responseTime) {
        return PortResult.builder(port, getScanType().getProtocol())
                .state(PortState.FILTERED)
                .reason("no-response")
                .responseTime(responseTime)
                .build();
    }

    /**
     * Get the reason string for open ports. Subclasses can override.
     */
    protected String getOpenReason() {
        return "syn-ack";
    }

    /**
     * Get the reason string for closed ports. Subclasses can override.
     */
    protected String getClosedReason() {
        return "conn-refused";
    }

    /**
     * Try to grab a service banner from the connection.
     */
    protected String tryGrabBanner(SocketChannel channel) {
        if (channel == null || !channel.isConnected()) {
            return null;
        }

        try {
            // Set a short timeout for banner grab
            channel.socket().setSoTimeout(2000);

            ByteBuffer buffer = ByteBuffer.allocate(1024);

            // Some services send banner immediately, try to read
            Selector readSelector = Selector.open();
            try {
                channel.register(readSelector, SelectionKey.OP_READ);
                int ready = readSelector.select(1000);

                if (ready > 0) {
                    int bytesRead = channel.read(buffer);
                    if (bytesRead > 0) {
                        buffer.flip();
                        byte[] data = new byte[buffer.remaining()];
                        buffer.get(data);
                        return new String(data).trim();
                    }
                }
            } finally {
                IOUtil.close(readSelector);
            }
        } catch (Exception e) {
            // Banner grab failed, that's ok
            if (log.isEnabled()) {
                log.getLogger().fine("Banner grab failed: " + e.getMessage());
            }
        }

        return null;
    }
//
//    private void closeQuietly(java.io.Closeable closeable) {
//        if (closeable != null) {
//            try {
//                closeable.close();
//            } catch (IOException e) {
//                // Ignore
//            }
//        }
//    }

    @Override
    public void stop() {
        // Cancel ongoing scans by shutting down executor
//        if (executor != null && !executor.isShutdown()) {
//            executor.shutdownNow();
//        }
    }

    @Override
    public int getActiveScans() {
        return activeScans.get();
    }

    @Override
    public void close() {
        if (!closed.getAndSet(true)) {

        }

//        if (executor != null) {
//            executor.shutdown();
//            try {
//                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
//                    executor.shutdownNow();
//                }
//            } catch (InterruptedException e) {
//                executor.shutdownNow();
//                Thread.currentThread().interrupt();
//            }
//        }
    }

    @Override
    public ExecutorService getExecutor() {
        return executor;
    }
//
//    @Override
//    public void asyncScanPort(String host, int port) {
//
//    }
//
//    @Override
//    public void asyncScanHost(String host, List<Integer> ports) {
//
//    }
}
