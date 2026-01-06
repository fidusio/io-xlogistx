package io.xlogistx.common.nmap.scan.tcp;

import io.xlogistx.common.nmap.config.NMapConfig;
import io.xlogistx.common.nmap.scan.*;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * TCP Connect scan engine implementation.
 * Uses pure Java NIO for non-blocking TCP connections to determine port state.
 */
public class TCPConnectScanEngine implements ScanEngine {

    public static final LogWrapper log = new LogWrapper(TCPConnectScanEngine.class).setEnabled(false);

    private NMapConfig config;
    private  ExecutorService executor;
    private volatile boolean initialized = false;
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicInteger activeScans = new AtomicInteger(0);
    private Semaphore parallelismLimiter;
    private boolean grabBanner = true;


    // Track pending results by host
    private final ConcurrentMap<String, List<CompletableFuture<PortResult>>> pendingByHost =
        new ConcurrentHashMap<>();

    private final List<PortResult> portScanResults = Collections.synchronizedList(new ArrayList<>());

    @Override
    public ScanType getScanType() {
        return ScanType.TCP_CONNECT;
    }

    @Override
    public String getDescription() {
        return "TCP Connect Scan - Full TCP connection to each port";
    }

    @Override
    public boolean isAvailable() {
        // TCP connect scan is always available (no raw sockets required)
        return true;
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

        return CompletableFuture.supplyAsync(() -> {
            try {
                log.getLogger().info("1-Semaphore permits: " + parallelismLimiter.availablePermits());
                parallelismLimiter.acquire();
                log.getLogger().info("2-Semaphore permits: " + parallelismLimiter.availablePermits());
                activeScans.incrementAndGet();
                try {
                    return performTcpConnect(host, port);
                } finally {
                    activeScans.decrementAndGet();
                    parallelismLimiter.release();
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
                Thread.currentThread().interrupt();
                return PortResult.error(port, "tcp", "interrupted");
            }
        }, executor);
    }

//    @Override
//    public void asyncScanPort(String host, int port) {
//        executor.submit(new CallableConsumer<PortResult>() {
//
//            /**
//             * Performs this operation on the given argument.
//             *
//             * @param o the input argument
//             */
//            @Override
//            public void accept(PortResult o) {
//                portScanResults.add(o);
//            }
//
//            public void exception(Exception e){
//                PortResult.error(port, "tcp", "interrupted");
//            }
//
//            /**
//             * Computes a result, or throws an exception if unable to do so.
//             *
//             * @return computed result
//             * @throws Exception if unable to compute a result
//             */
//            @Override
//            public PortResult call() throws Exception {
//
//                activeScans.incrementAndGet();
//                try {
//                    return performTcpConnect(host, port);
//                } finally {
//                    activeScans.decrementAndGet();
//                }
//            }
//
//        });
//    }

//    @Override
//    public void asyncScanHost(String host, List<Integer> ports) {
//
//    }

    /**
     * Perform TCP connect scan using NIO SocketChannel.
     */
    private PortResult performTcpConnect(String host, int port) {
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
            //boolean connected = channel.connect(address);

            if (!channel.connect(address)) {
                // Connection in progress, wait for completion
                channel.register(selector, SelectionKey.OP_CONNECT);

                int readyCount = selector.select(timeoutMs);

                if (readyCount == 0) {
                    // Timeout - port is filtered
                    long responseTime = System.currentTimeMillis() - startTime;
                    return PortResult.builder(port, "tcp")
                        .state(PortState.FILTERED)
                        .reason("no-response")
                        .responseTime(responseTime)
                        .build();
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

            // Fallback
            long responseTime = System.currentTimeMillis() - startTime;
            return PortResult.builder(port, "tcp")
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
            return PortResult.builder(port, "tcp")
                .state(PortState.FILTERED)
                .reason("no-route")
                .responseTime(responseTime)
                .build();
        } catch (SocketTimeoutException e) {
            // Timeout - port is filtered
            long responseTime = System.currentTimeMillis() - startTime;
            return PortResult.builder(port, "tcp")
                .state(PortState.FILTERED)
                .reason("timeout")
                .responseTime(responseTime)
                .build();
        } catch (IOException e) {
            long responseTime = System.currentTimeMillis() - startTime;
            String reason = e.getMessage();

            // Analyze the exception to determine port state
            if (reason != null && reason.toLowerCase().contains("refused")) {
                return createClosedResult(port, responseTime, e);
            } else if (reason != null && reason.toLowerCase().contains("reset")) {
                return createClosedResult(port, responseTime, e);
            }

            return PortResult.builder(port, "tcp")
                .state(PortState.FILTERED)
                .reason("error: " + reason)
                .responseTime(responseTime)
                .build();
        } finally {
            IOUtil.close(selector, channel);
        }
    }

    /**
     * Create an OPEN port result with optional banner grabbing.
     */
    private PortResult createOpenResult(int port, long responseTime, SocketChannel channel) {
        PortResult.Builder builder = PortResult.builder(port, "tcp")
            .state(PortState.OPEN)
            .reason("syn-ack")
            .responseTime(responseTime);

        // Try to grab banner if service detection is enabled
        if (grabBanner && channel != null && channel.isConnected()) {
            String banner = tryGrabBanner(channel);
            if (banner != null && !banner.isEmpty()) {
                builder.banner(banner);
            }
        }

        return builder.build();
    }

    /**
     * Create a CLOSED port result.
     */
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

    /**
     * Try to grab a service banner from the connection.
     */
    private String tryGrabBanner(SocketChannel channel) {
        if (channel == null || !channel.isConnected()) {
            return null;
        }

        Selector readSelector = null;
        try {
            ByteBuffer buffer = ByteBuffer.allocate(1024);

            readSelector = Selector.open();
            channel.register(readSelector, SelectionKey.OP_READ);
            int ready = readSelector.select(1000); // 1 second timeout for banner

            if (ready > 0) {
                int bytesRead = channel.read(buffer);
                if (bytesRead > 0) {
                    buffer.flip();
                    byte[] data = new byte[buffer.remaining()];
                    buffer.get(data);
                    return new String(data).trim();
                }
            }
        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().fine("Banner grab failed: " + e.getMessage());
            }
        } finally {
            IOUtil.close(readSelector);
        }

        return null;
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

        // Create futures for all port scans
        List<CompletableFuture<PortResult>> futures = new ArrayList<>();

        for (int port : ports) {
            log.getLogger().info("Scanning on port " + port);
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

        // Store pending futures for this host
        pendingByHost.put(host, futures);

        // Combine all futures
        CompletableFuture<Void> allOf = CompletableFuture.allOf(
            futures.toArray(new CompletableFuture[0])
        );

        return allOf.thenApply(v -> {
            long endTime = System.currentTimeMillis();
            pendingByHost.remove(host);

            // Collect results
            List<PortResult> results = new ArrayList<>();
            boolean hostUp = false;

            for (CompletableFuture<PortResult> future : futures) {
                try {
                    PortResult result = future.get();
                    log.getLogger().info("after get " + result);
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

            // Build scan result
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

            // Return a result indicating scan failure
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
//        log.getLogger().info("Stopping engine ...");
        // Cancel all pending scans
        for (List<CompletableFuture<PortResult>> futures : pendingByHost.values()) {
            for (CompletableFuture<PortResult> future : futures) {
                if (!future.isDone()) {
                    future.cancel(true);
                }
            }
        }
        pendingByHost.clear();
//        log.getLogger().info("Stopping engine finished ...");
    }

    @Override
    public int getActiveScans() {
        return activeScans.get();
    }

    @Override
    public void close() {
        if (!closed.getAndSet(false))
            stop();

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



    private void checkInitialized() {
        if (!initialized) {
            throw new IllegalStateException("Engine not initialized. Call init() first.");
        }
    }
}
