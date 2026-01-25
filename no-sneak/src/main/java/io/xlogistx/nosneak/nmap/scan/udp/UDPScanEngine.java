package io.xlogistx.nosneak.nmap.scan.udp;

import io.xlogistx.nosneak.nmap.config.NMapConfig;
import io.xlogistx.nosneak.nmap.scan.*;
import io.xlogistx.nosneak.nmap.util.*;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.shared.util.Const;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.PortUnreachableException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * UDP scan engine implementation using NIOSocket callbacks.
 * Uses shared NIOSocket event loop for efficient non-blocking UDP scanning.
 */
public class UDPScanEngine implements ScanEngine {

    public static final LogWrapper log = new LogWrapper(UDPScanEngine.class).setEnabled(false);

    private NMapConfig config;
    private ExecutorService executor;
    private NIOSocket nioSocket;
    private UDPPortScanCallback scanCallback;
    private volatile boolean initialized = false;
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicInteger activeScans = new AtomicInteger(0);
    private Semaphore parallelismLimiter;

    private final ConcurrentMap<String, List<CompletableFuture<PortResult>>> pendingByHost =
            new ConcurrentHashMap<>();




    @Override
    public ScanType getScanType() {
        return ScanType.UDP;
    }

    @Override
    public String getDescription() {
        return "UDP Scan - NIO callback-based UDP probes to detect open ports";
    }

    @Override
    public boolean isAvailable() {
        // UDP scan is always available (no raw sockets required)
        return true;
    }

    @Override
    public void setNIOSocket(NIOSocket nioSocket) {
        this.nioSocket = nioSocket;

        // Create and register the UDP scan callback
        if (nioSocket != null && scanCallback == null) {
            try {
                scanCallback = new UDPPortScanCallback();
                scanCallback.setExecutor(nioSocket.getExecutor());
                nioSocket.addDatagramSocket(scanCallback);

                if (log.isEnabled()) {
                    log.getLogger().info("UDP scan callback registered with NIOSocket");
                }
            } catch (IOException e) {
                log.getLogger().warning("Failed to register UDP callback: " + e.getMessage());
                scanCallback = null;
            }
        }
    }

    @Override
    public void init(ExecutorService executor, NMapConfig config) {
        if (initialized) {
            throw new IllegalStateException("Engine already initialized");
        }

        this.config = config;
        this.parallelismLimiter = new Semaphore(config.getMaxParallelism());
        this.executor = executor;
        this.initialized = true;

        if (log.isEnabled()) {
            log.getLogger().info("UDPScanEngine initialized with parallelism: " +
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

        // Use NIOSocket callback if available, otherwise fall back to blocking approach
        if (nioSocket != null && scanCallback != null) {
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

            int timeoutMs = config.getTimeoutSec() * 1000;
            if (timeoutMs <= 0) {
                timeoutMs = 10000; // 10 second default for UDP
            }

            if (log.isEnabled()) {
                log.getLogger().info("Scanning UDP " + host + ":" + port + " with NIOSocket");
            }

            scanCallback.sendProbe(host, port, timeoutMs, result -> {
                activeScans.decrementAndGet();
                parallelismLimiter.release();
                future.complete(result);
            });

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            activeScans.decrementAndGet();
            parallelismLimiter.release();
            future.complete(PortResult.error(port, "udp", "interrupted"));
        } catch (Exception e) {
            activeScans.decrementAndGet();
            parallelismLimiter.release();

            if (log.isEnabled()) {
                log.getLogger().warning("Error scanning UDP " + host + ":" + port + ": " + e.getMessage());
            }

            future.complete(PortResult.error(port, "udp", e.getMessage()));
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
                    return performBlockingUdpScan(host, port);
                } finally {
                    activeScans.decrementAndGet();
                    parallelismLimiter.release();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return PortResult.error(port, "udp", "interrupted");
            }
        }, executor).thenAccept(future::complete);
    }

    /**
     * Blocking UDP scan for fallback mode.
     */
    private PortResult performBlockingUdpScan(String host, int port) {
        long startTime = System.currentTimeMillis();

        int timeoutMs = config.getTimeoutSec() * 1000;
        if (timeoutMs <= 0) {
            timeoutMs = 10000; // 10 second default for UDP
        }

        DatagramChannel channel = null;
        Selector selector = null;

        try {
            channel = DatagramChannel.open();
            channel.configureBlocking(false);

            InetSocketAddress address = new InetSocketAddress(host, port);
            channel.connect(address);

            selector = Selector.open();

            // Send probe packet
            byte[] probe = getProbeForPort(port);
            if (probe.length > 0) {
                ByteBuffer sendBuffer = ByteBuffer.wrap(probe);
                channel.write(sendBuffer);
            } else {
                // Send empty packet
                ByteBuffer sendBuffer = ByteBuffer.allocate(1);
                sendBuffer.put((byte) 0);
                sendBuffer.flip();
                channel.write(sendBuffer);
            }

            // Wait for response
            channel.register(selector, SelectionKey.OP_READ);
            int readyCount = selector.select(timeoutMs);

            if (readyCount == 0) {
                // No response - could be open or filtered
                long responseTime = System.currentTimeMillis() - startTime;
                return PortResult.builder(port, "udp")
                        .state(PortState.OPEN_FILTERED)
                        .reason("no-response")
                        .responseTime(responseTime)
                        .build();
            }

            Set<SelectionKey> keys = selector.selectedKeys();
            Iterator<SelectionKey> iter = keys.iterator();

            while (iter.hasNext()) {
                SelectionKey key = iter.next();
                iter.remove();

                if (key.isReadable()) {
                    ByteBuffer buffer = ByteBuffer.allocate(1024);
                    try {
                        int bytesRead = channel.read(buffer);
                        if (bytesRead > 0) {
                            // Got response - port is open
                            long responseTime = System.currentTimeMillis() - startTime;
                            buffer.flip();
                            byte[] data = new byte[buffer.remaining()];
                            buffer.get(data);

                            return PortResult.builder(port, "udp")
                                    .state(PortState.OPEN)
                                    .reason("udp-response")
                                    .responseTime(responseTime)
                                    .banner(new String(data).trim())
                                    .build();
                        }
                    } catch (PortUnreachableException e) {
                        // ICMP port unreachable - port is closed
                        long responseTime = System.currentTimeMillis() - startTime;
                        return PortResult.builder(port, "udp")
                                .state(PortState.CLOSED)
                                .reason("port-unreach")
                                .responseTime(responseTime)
                                .build();
                    }
                }
            }

            // No response after selection
            long responseTime = System.currentTimeMillis() - startTime;
            return PortResult.builder(port, "udp")
                    .state(PortState.OPEN_FILTERED)
                    .reason("no-response")
                    .responseTime(responseTime)
                    .build();

        } catch (PortUnreachableException e) {
            // ICMP port unreachable - port is closed
            long responseTime = System.currentTimeMillis() - startTime;
            return PortResult.builder(port, "udp")
                    .state(PortState.CLOSED)
                    .reason("port-unreach")
                    .responseTime(responseTime)
                    .build();
        } catch (IOException e) {
            long responseTime = System.currentTimeMillis() - startTime;
            String reason = e.getMessage();

            if (reason != null && reason.toLowerCase().contains("unreachable")) {
                return PortResult.builder(port, "udp")
                        .state(PortState.CLOSED)
                        .reason("port-unreach")
                        .responseTime(responseTime)
                        .build();
            }

            return PortResult.builder(port, "udp")
                    .state(PortState.OPEN_FILTERED)
                    .reason("error: " + reason)
                    .responseTime(responseTime)
                    .build();
        } finally {
            IOUtil.close(selector, channel);
        }
    }

    /**
     * Get appropriate probe payload for the port.
     */
    private byte[] getProbeForPort(int port) {
        switch (port) {
            case 53:    // DNS
                return PacketDataConst.DNS_PROBE;
            case 161:   // SNMP
            case 162:
                return PacketDataConst.SNMP_PROBE;
            default:
                return Const.EMPTY_BYTE_ARRAY;
        }
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
                log.getLogger().info("Scanning UDP port " + port);
            }
            CompletableFuture<PortResult> future = scanPort(host, port);
            futures.add(future);

            // UDP scans typically need more delay to avoid overwhelming
            long delay = config.getTiming().getProbeDelayMs();
            if (delay <= 0) {
                delay = 100; // Minimum 100ms between UDP probes
            }

            try {
                Thread.sleep(delay);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
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
                        log.getLogger().warning("UDP port scan failed: " + e.getMessage());
                    }
                }
            }

            return ScanResult.builder(host)
                    .resolveAddress()
                    .hostUp(hostUp)
                    .hostUpReason(hostUp ? "udp-response" : "no-response")
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
            // Close the scan callback
            IOUtil.close(scanCallback);
            scanCallback = null;
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
