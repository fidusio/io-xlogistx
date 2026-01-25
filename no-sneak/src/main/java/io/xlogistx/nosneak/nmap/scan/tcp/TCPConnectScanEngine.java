package io.xlogistx.nosneak.nmap.scan.tcp;

import io.xlogistx.nosneak.nmap.config.NMapConfig;
import io.xlogistx.nosneak.nmap.scan.*;
import io.xlogistx.nosneak.nmap.util.PortResult;
import io.xlogistx.nosneak.nmap.util.PortState;
import io.xlogistx.nosneak.nmap.util.ScanResult;
import io.xlogistx.nosneak.nmap.util.ScanType;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.shared.net.IPAddress;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * TCP Connect scan engine implementation using NIOSocket callbacks.
 * Uses shared NIOSocket event loop for efficient non-blocking TCP connections.
 */
public class TCPConnectScanEngine implements ScanEngine {

    public static final LogWrapper log = new LogWrapper(TCPConnectScanEngine.class).setEnabled(false);

    private NMapConfig config;
    private ExecutorService executor;
    private NIOSocket nioSocket;
    private volatile boolean initialized = false;
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicInteger activeScans = new AtomicInteger(0);
    private Semaphore parallelismLimiter;
    private boolean grabBanner = true;

    // Track pending results by host
    private final ConcurrentMap<String, List<CompletableFuture<PortResult>>> pendingByHost =
            new ConcurrentHashMap<>();

    @Override
    public ScanType getScanType() {
        return ScanType.TCP_CONNECT;
    }

    @Override
    public String getDescription() {
        return "TCP Connect Scan - NIO callback-based TCP connection to each port";
    }

    @Override
    public boolean isAvailable() {
        // TCP connect scan is always available (no raw sockets required)
        return true;
    }

    @Override
    public void setNIOSocket(NIOSocket nioSocket) {
        this.nioSocket = nioSocket;
    }

    @Override
    public void init(ExecutorService executor, NMapConfig config) {
        if (initialized) {
            throw new IllegalStateException("Engine already initialized");
        }

        this.config = config;
        this.grabBanner = config.isServiceDetection();
        this.parallelismLimiter = new Semaphore(config.getMaxParallelism());
        this.executor = executor;
        this.initialized = true;

        if (log.isEnabled()) {
            log.getLogger().info("TCPConnectScanEngine initialized with parallelism: " +
                    config.getMaxParallelism());
        }
    }

    @Override
    public CompletableFuture<PortResult> scanPort(String host, int port) {
        checkInitialized();

        if (closed.get()) {
            CompletableFuture<PortResult> closedFuture = new CompletableFuture<>();
            closedFuture.completeExceptionally(new IllegalStateException("Engine is closed"));
            return closedFuture;
        }

        CompletableFuture<PortResult> future = new CompletableFuture<>();

        // Use NIOSocket if available, otherwise fall back to blocking approach
        if (nioSocket != null) {
            scanPortWithNIOSocket(host, port, future);
        } else {
            scanPortBlocking(host, port, future);
        }

        return future;
    }

    /**
     * Scan port using NIOSocket callback pattern (non-blocking).
     */
    private void scanPortWithNIOSocket(String host, int port, CompletableFuture<PortResult> future) {
        try {
            parallelismLimiter.acquire();
            activeScans.incrementAndGet();

            IPAddress address = new IPAddress(host, port);
            TCPPortScanCallback callback = new TCPPortScanCallback(
                    address,
                    result -> {
                        activeScans.decrementAndGet();
                        parallelismLimiter.release();
                        future.complete(result);
                    },
                    grabBanner
            );

            int timeoutSec = config.getTimeoutSec();
            if (timeoutSec <= 0) {
                timeoutSec = 5;
            }

            if (log.isEnabled()) {
                log.getLogger().info("Scanning " + host + ":" + port + " with NIOSocket");
            }

            nioSocket.addClientSocket(callback, timeoutSec);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            activeScans.decrementAndGet();
            parallelismLimiter.release();
            future.complete(PortResult.error(port, "tcp", "interrupted"));
        } catch (Exception e) {
            activeScans.decrementAndGet();
            parallelismLimiter.release();

            if (log.isEnabled()) {
                log.getLogger().warning("Error scanning " + host + ":" + port + ": " + e.getMessage());
            }

            future.complete(PortResult.error(port, "tcp", e.getMessage()));
        }
    }

    /**
     * Fallback blocking scan for when NIOSocket is not available.
     */
    private void scanPortBlocking(String host, int port, CompletableFuture<PortResult> future) {
        CompletableFuture.supplyAsync(() -> {
            try {
                parallelismLimiter.acquire();
                activeScans.incrementAndGet();
                try {
                    return performBlockingTcpConnect(host, port);
                } finally {
                    activeScans.decrementAndGet();
                    parallelismLimiter.release();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return PortResult.error(port, "tcp", "interrupted");
            }
        }, executor).thenAccept(future::complete);
    }

    /**
     * Blocking TCP connect for fallback mode.
     */
    private PortResult performBlockingTcpConnect(String host, int port) {
        long startTime = System.currentTimeMillis();
        int timeoutMs = config.getTimeoutSec() * 1000;
        if (timeoutMs <= 0) {
            timeoutMs = 5000;
        }

        java.nio.channels.SocketChannel channel = null;
        java.nio.channels.Selector selector = null;

        try {
            channel = java.nio.channels.SocketChannel.open();
            channel.configureBlocking(false);
            selector = java.nio.channels.Selector.open();

            java.net.InetSocketAddress address = new java.net.InetSocketAddress(host, port);

            if (!channel.connect(address)) {
                channel.register(selector, java.nio.channels.SelectionKey.OP_CONNECT);
                int readyCount = selector.select(timeoutMs);

                if (readyCount == 0) {
                    long responseTime = System.currentTimeMillis() - startTime;
                    return PortResult.builder(port, "tcp")
                            .state(PortState.FILTERED)
                            .reason("no-response")
                            .responseTime(responseTime)
                            .build();
                }

                for (java.nio.channels.SelectionKey key : selector.selectedKeys()) {
                    if (key.isConnectable()) {
                        try {
                            if (channel.finishConnect()) {
                                long responseTime = System.currentTimeMillis() - startTime;
                                return PortResult.builder(port, "tcp")
                                        .state(PortState.OPEN)
                                        .reason("syn-ack")
                                        .responseTime(responseTime)
                                        .build();
                            }
                        } catch (java.io.IOException e) {
                            long responseTime = System.currentTimeMillis() - startTime;
                            return createClosedResult(port, responseTime, e);
                        }
                    }
                }
            } else {
                long responseTime = System.currentTimeMillis() - startTime;
                return PortResult.builder(port, "tcp")
                        .state(PortState.OPEN)
                        .reason("syn-ack")
                        .responseTime(responseTime)
                        .build();
            }

            long responseTime = System.currentTimeMillis() - startTime;
            return PortResult.builder(port, "tcp")
                    .state(PortState.UNKNOWN)
                    .reason("unknown")
                    .responseTime(responseTime)
                    .build();

        } catch (java.net.ConnectException e) {
            long responseTime = System.currentTimeMillis() - startTime;
            return createClosedResult(port, responseTime, e);
        } catch (java.io.IOException e) {
            long responseTime = System.currentTimeMillis() - startTime;
            String reason = e.getMessage();
            if (reason != null && (reason.toLowerCase().contains("refused") ||
                    reason.toLowerCase().contains("reset"))) {
                return createClosedResult(port, responseTime, e);
            }
            return PortResult.builder(port, "tcp")
                    .state(PortState.FILTERED)
                    .reason("error: " + reason)
                    .responseTime(responseTime)
                    .build();
        } finally {
            org.zoxweb.server.io.IOUtil.close(selector, channel);
        }
    }

    private PortResult createClosedResult(int port, long responseTime, Exception e) {
        String reason = "conn-refused";
        if (e != null && e.getMessage() != null) {
            if (e.getMessage().toLowerCase().contains("reset")) {
                reason = "reset";
            }
        }
        return PortResult.builder(port, "tcp")
                .state(PortState.CLOSED)
                .reason(reason)
                .responseTime(responseTime)
                .build();
    }

    @Override
    public CompletableFuture<ScanResult> scanHost(String host, List<Integer> ports) {
        checkInitialized();

        if (closed.get()) {
            CompletableFuture<ScanResult> closedFuture = new CompletableFuture<>();
            closedFuture.completeExceptionally(new IllegalStateException("Engine is closed"));
            return closedFuture;
        }

        long startTime = System.currentTimeMillis();

        List<CompletableFuture<PortResult>> futures = new ArrayList<>();

        for (int port : ports) {
            if (log.isEnabled()) {
                log.getLogger().info("Scanning port " + port);
            }
            CompletableFuture<PortResult> future = scanPort(host, port);
            futures.add(future);

            // Apply delay between probes if configured
            if (config.getTiming().getProbeDelayMs() > 0) {
                try {
                    Thread.sleep(config.getTiming().getProbeDelayMs());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }

        pendingByHost.put(host, futures);

        CompletableFuture<Void> allOf = CompletableFuture.allOf(
                futures.toArray(new CompletableFuture[0])
        );

        return allOf.thenApply(v -> {
            long endTime = System.currentTimeMillis();
            pendingByHost.remove(host);

            List<PortResult> results = new ArrayList<>();
            boolean hostUp = false;

            for (CompletableFuture<PortResult> future : futures) {
                // Use join() instead of get() - futures are already complete after allOf()
                // join() throws unchecked CompletionException instead of checked exceptions
                try {
                    PortResult result = future.join();
                    if (log.isEnabled()) {
                        log.getLogger().info("Result: " + result);
                    }
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

            return ScanResult.builder(host)
                    .resolveAddress()
                    .hostUp(hostUp)
                    .hostUpReason(hostUp ? "tcp-response" : "no-response")
                    .startTime(startTime)
                    .endTime(endTime)
                    .portResults(results)
                    .build();
        }).exceptionally(e -> {
            pendingByHost.remove(host);

            return ScanResult.builder(host)
                    .resolveAddress()
                    .hostUp(false)
                    .hostUpReason("error: " + e.getMessage())
                    .startTime(startTime)
                    .endTime(System.currentTimeMillis())
                    .build();
        });
    }

    @Override
    public void stop() {
        for (List<CompletableFuture<PortResult>> futures : pendingByHost.values()) {
            for (CompletableFuture<PortResult> future : futures) {
                if (!future.isDone()) {
                    future.cancel(true);
                }
            }
        }
        pendingByHost.clear();
    }

    @Override
    public int getActiveScans() {
        return activeScans.get();
    }

    @Override
    public void close() {
        if (!closed.getAndSet(true)) {
            stop();
        }
    }

    @Override
    public ExecutorService getExecutor() {
        return executor;
    }

    private void checkInitialized() {
        if (!initialized) {
            throw new IllegalStateException("Engine not initialized. Call init() first.");
        }
    }
}
