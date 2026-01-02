package io.xlogistx.common.nmap.scan.udp;

import io.xlogistx.common.nmap.config.NMapConfig;
import io.xlogistx.common.nmap.scan.*;
import org.zoxweb.server.logging.LogWrapper;
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
 * UDP scan engine implementation.
 * Uses pure Java NIO DatagramChannel for non-blocking UDP scanning.
 */
public class UDPScanEngine implements ScanEngine {

    public static final LogWrapper log = new LogWrapper(UDPScanEngine.class).setEnabled(false);

    private NMapConfig config;
    private  ExecutorService executor;
    private volatile boolean initialized = false;
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicInteger activeScans = new AtomicInteger(0);
    private Semaphore parallelismLimiter;

    private final ConcurrentMap<String, List<CompletableFuture<PortResult>>> pendingByHost =
        new ConcurrentHashMap<>();

    // UDP probe payloads for common services
    private static final byte[] DNS_PROBE = new byte[]{
        0x00, 0x00,  // Transaction ID
        0x01, 0x00,  // Flags: standard query
        0x00, 0x01,  // Questions: 1
        0x00, 0x00,  // Answer RRs: 0
        0x00, 0x00,  // Authority RRs: 0
        0x00, 0x00,  // Additional RRs: 0
        0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n',  // Query: version
        0x04, 'b', 'i', 'n', 'd',                  // .bind
        0x00,        // Root
        0x00, 0x10,  // Type: TXT
        0x00, 0x03   // Class: CH
    };

    private static final byte[] SNMP_PROBE = new byte[]{
        0x30, 0x26,              // Sequence
        0x02, 0x01, 0x00,        // Version: 1
        0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',  // Community: public
        (byte) 0xa0, 0x19,       // Get-Request PDU
        0x02, 0x04, 0x00, 0x00, 0x00, 0x00,  // Request ID
        0x02, 0x01, 0x00,        // Error status
        0x02, 0x01, 0x00,        // Error index
        0x30, 0x0b,              // Varbind list
        0x30, 0x09,              // Varbind
        0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01,  // OID: 1.3.6.1.2.1
        0x05, 0x00               // Value: NULL
    };


    @Override
    public ScanType getScanType() {
        return ScanType.UDP;
    }

    @Override
    public String getDescription() {
        return "UDP Scan - Send UDP probes to detect open ports";
    }

    @Override
    public boolean isAvailable() {
        // UDP scan is always available (no raw sockets required)
        return true;
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
            log.getLogger().info("UDPScanEngine initialized");
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
                parallelismLimiter.acquire();
                activeScans.incrementAndGet();
                try {
                    return performUdpScan(host, port);
                } finally {
                    activeScans.decrementAndGet();
                    parallelismLimiter.release();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return PortResult.error(port, "udp", "interrupted");
            }
        }, executor);
    }

    /**
     * Perform UDP scan using DatagramChannel.
     */
    private PortResult performUdpScan(String host, int port) {
        long startTime = System.currentTimeMillis();

        // UDP scans typically need longer timeouts
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
            closeQuietly(selector);
            closeQuietly(channel);
        }
    }

    /**
     * Get appropriate probe payload for the port.
     */
    private byte[] getProbeForPort(int port) {
        switch (port) {
            case 53:    // DNS
                return DNS_PROBE;
            case 161:   // SNMP
            case 162:
                return SNMP_PROBE;
            default:
                return Const.EMPTY_BYTE_ARRAY;
        }
    }

    private void closeQuietly(java.io.Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException e) {
                // Ignore
            }
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
                try {
                    PortResult result = future.get();
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
        if (!closed.getAndSet(true))
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
