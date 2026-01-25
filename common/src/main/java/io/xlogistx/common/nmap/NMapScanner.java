package io.xlogistx.common.nmap;

import io.xlogistx.common.nmap.config.NMapConfig;
import io.xlogistx.common.nmap.config.PortSpecification;
import io.xlogistx.common.nmap.config.TargetSpecification;
import io.xlogistx.common.nmap.config.TimingTemplate;
import io.xlogistx.common.nmap.output.OutputFormat;
import io.xlogistx.common.nmap.output.ScanReport;
import io.xlogistx.common.nmap.scan.ScanEngine;
import io.xlogistx.common.nmap.scan.ScanResult;
import io.xlogistx.common.nmap.scan.ScanType;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.task.ConsumerCallback;

import java.io.Closeable;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Main NMap scanner orchestrator.
 * Coordinates scan engines, collects results, and generates reports.
 *
 * All scan engines use pure Java NIO (SocketChannel, DatagramChannel, Selector)
 * and do not require external system commands.
 */
public class NMapScanner implements Closeable {

    public static final LogWrapper log = new LogWrapper(NMapScanner.class).setEnabled(false);

    private final NMapConfig config;
    private final Map<ScanType, ScanEngine> engines;
    private final ExecutorService executor;
    private NIOSocket nioSocket;
    private volatile boolean running = false;
    private final AtomicBoolean closed = new AtomicBoolean(false);

    private NMapScanner(ExecutorService executor, NMapConfig config) {
        this(executor, config, null);
    }

    private NMapScanner(ExecutorService executor, NMapConfig config, NIOSocket nioSocket) {
        this.config = config;
        this.engines = new EnumMap<>(ScanType.class);
        this.executor = executor;
        this.nioSocket = nioSocket;
    }

    /**
     * Create a scanner with the given configuration
     */
    public static NMapScanner create(ExecutorService executor, NMapConfig config) {
        return new NMapScanner(executor, config);
    }

    /**
     * Create a scanner with the given configuration and NIOSocket.
     * Using NIOSocket enables efficient callback-based scanning with a shared event loop.
     *
     * @param executor the executor service for async operations
     * @param config the scan configuration
     * @param nioSocket the shared NIOSocket instance for callback-based scanning
     */
    public static NMapScanner create(ExecutorService executor, NMapConfig config, NIOSocket nioSocket) {
        return new NMapScanner(executor, config, nioSocket);
    }

    /**
     * Set the NIOSocket for callback-based scanning.
     * This will be passed to engines that support NIOSocket.
     *
     * @param nioSocket the shared NIOSocket instance
     */
    public void setNIOSocket(NIOSocket nioSocket) {
        this.nioSocket = nioSocket;
        // Update existing engines with the new NIOSocket
        for (ScanEngine engine : engines.values()) {
            engine.setNIOSocket(nioSocket);
        }
    }

    /**
     * Get the NIOSocket instance.
     *
     * @return the NIOSocket, or null if not configured
     */
    public NIOSocket getNIOSocket() {
        return nioSocket;
    }


    /**
     * Register a scan engine for a specific scan type.
     * If NIOSocket is configured, it will be passed to the engine for
     * efficient callback-based scanning.
     */
    public NMapScanner registerEngine(ScanEngine engine) {
        engine.init(TaskUtil.defaultTaskProcessor(), config);
        // Pass NIOSocket to engine if available
        if (nioSocket != null) {
            engine.setNIOSocket(nioSocket);
        }
        engines.put(engine.getScanType(), engine);
        return this;
    }

    /**
     * Get the engine for a scan type
     */
    public ScanEngine getEngine(ScanType type) {
        return engines.get(type);
    }

    /**
     * Perform the scan according to configuration.
     * This is a blocking call that returns when the scan is complete.
     */
    public ScanReport scan() throws InterruptedException, ExecutionException {
        return scanAsync().get();
    }

    /**
     * Perform the scan asynchronously using scanStreaming() - no join() or blocking.
     */
    public CompletableFuture<ScanReport> scanAsync() {
        long startTime = System.currentTimeMillis();
        TargetSpecification targets = config.getTargets();
        PortSpecification ports = config.getPorts();
        ScanType primaryType = config.getPrimaryScanType();

        // Collect results as they stream in
        List<ScanResult> results = Collections.synchronizedList(new ArrayList<>());

        // Use scanStreaming and build report when complete
        return scanStreaming(new ConsumerCallback<ScanResult>() {
            @Override
            public void accept(ScanResult result) {
                log.getLogger().info("Scan result: " + result);
                results.add(result);
            }

            @Override
            public void exception(Exception e) {
                log.getLogger().info("Scan error: " + e.getMessage());
            }
        }).thenApply(v -> {
            long endTime = System.currentTimeMillis();

            return ScanReport.builder()
                .config(config)
                .startTime(startTime)
                .endTime(endTime)
                .hostResults(results)
                .addStatistic("total_hosts", targets.getTargetCount())
                .addStatistic("total_ports_per_host", ports.getTotalPortCount())
                .addStatistic("scan_type", primaryType.name())
                .addStatistic("timing", config.getTiming().name())
                .build();
        });
    }

    /**
     * Perform scan with streaming results - callback invoked as each host completes.
     * No join() or blocking - results stream as they become available.
     *
     * @param callback receives each ScanResult as it completes; exception() called on errors
     * @return CompletableFuture that completes when all scans finish
     */
    public CompletableFuture<Void> scanStreaming(ConsumerCallback<ScanResult> callback) {
        if (closed.get()) {
            CompletableFuture<Void> future = new CompletableFuture<>();
            future.completeExceptionally(new IllegalStateException("Scanner is closed"));
            return future;
        }

        if (running) {
            CompletableFuture<Void> future = new CompletableFuture<>();
            future.completeExceptionally(new IllegalStateException("Scan already in progress"));
            return future;
        }

        running = true;

        // Get the primary scan engine
        ScanType primaryType = config.getPrimaryScanType();
        ScanEngine engine = engines.get(primaryType);

        if (engine == null) {
            running = false;
            CompletableFuture<Void> future = new CompletableFuture<>();
            future.completeExceptionally(new IllegalStateException(
                "No engine registered for scan type: " + primaryType));
            return future;
        }

        if (!engine.isAvailable()) {
            log.getLogger().info("Engine not available: " + primaryType +
                ", falling back to TCP_CONNECT");
            engine = engines.get(ScanType.TCP_CONNECT);
            if (engine == null) {
                running = false;
                CompletableFuture<Void> future = new CompletableFuture<>();
                future.completeExceptionally(new IllegalStateException("No fallback engine available"));
                return future;
            }
        }

        TargetSpecification targets = config.getTargets();
        List<Integer> portsToScan = getPortsForEngine(engine);
        List<CompletableFuture<Void>> completionFutures = new ArrayList<>();

        for (String target : targets.getTargets()) {
            if (log.isEnabled()) {
                log.getLogger().info("Scanning " + target + " with " + portsToScan.size() + " ports");
            }

            // Scan host and invoke callback when complete - no blocking
            CompletableFuture<Void> hostFuture = engine.scanHost(target, portsToScan)
                .thenAccept(result -> {
                    try {
                        callback.accept(result);
                    } catch (Exception e) {
                        log.getLogger().warning("Callback error for " + target + ": " + e.getMessage());
                    }
                })
                .exceptionally(e -> {
                    callback.exception(e instanceof Exception ? (Exception) e : new Exception(e));
                    return null;
                });

            completionFutures.add(hostFuture);
        }

        // Return a future that completes when ALL hosts are done (but doesn't block)
        return CompletableFuture.allOf(completionFutures.toArray(new CompletableFuture[0]))
            .whenComplete((v, e) -> running = false);
    }

    /**
     * Get ports to scan for the given engine
     */
    private List<Integer> getPortsForEngine(ScanEngine engine) {
        PortSpecification ports = config.getPorts();

        if (engine.getScanType().isTcp()) {
            return ports.getTcpPortList();
        } else if (engine.getScanType().isUdp()) {
            return ports.getUdpPortList();
        }

        // Default to TCP ports
        return ports.getTcpPortList();
    }

    /**
     * Stop any in-progress scan
     */
    public void stop() {
        for (ScanEngine engine : engines.values()) {
            try {
                engine.close();
            } catch (Exception e) {
                log.getLogger().warning("Error closing engine: " + e.getMessage());
            }
        }
    }

    /**
     * Check if a scan is currently running
     */
    public boolean isRunning() {
        return running;
    }

    /**
     * Check if the scanner is closed
     */
    public boolean isClosed() {
        return closed.get();
    }

    /**
     * Get the configuration
     */
    public NMapConfig getConfig() {
        return config;
    }

    /**
     * Get scanner statistics
     */
    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("running", running);
        stats.put("closed", closed);
        stats.put("engines", engines.size());

        int totalActive = 0;
        for (ScanEngine engine : engines.values()) {
            totalActive += engine.getActiveScans();
        }
        stats.put("active_scans", totalActive);

        return stats;
    }

    @Override
    public void close() {
        if (!closed.getAndSet(true))
            stop();

    }

    /**
     * Builder for creating NMapScanner instances
     */
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private final NMapConfig.Builder configBuilder = NMapConfig.builder();
        private final List<ScanEngine> customEngines = new ArrayList<>();
        private NIOSocket nioSocket;

        public Builder target(String target) {
            configBuilder.target(target);
            return this;
        }

        public Builder targets(String... targets) {
            configBuilder.targets(targets);
            return this;
        }

        public Builder ports(String portSpec) {
            configBuilder.ports(portSpec);
            return this;
        }

        public Builder topPorts(int count) {
            configBuilder.topPorts(count);
            return this;
        }

        public Builder scanType(ScanType type) {
            configBuilder.scanType(type);
            return this;
        }

        public Builder timing(TimingTemplate timing) {
            configBuilder.timing(timing);
            return this;
        }

        public Builder timing(String timing) {
            configBuilder.timing(timing);
            return this;
        }

        public Builder timeout(int seconds) {
            configBuilder.timeout(seconds);
            return this;
        }

        public Builder serviceDetection(boolean enable) {
            configBuilder.serviceDetection(enable);
            return this;
        }

        public Builder osDetection(boolean enable) {
            configBuilder.osDetection(enable);
            return this;
        }

        public Builder verbose(boolean enable) {
            configBuilder.verbose(enable);
            return this;
        }

        public Builder outputFormat(OutputFormat format) {
            configBuilder.outputFormat(format);
            return this;
        }

        /**
         * Set the NIOSocket for efficient callback-based scanning.
         * This enables the scanner to use a shared event loop instead of
         * creating per-port selectors.
         *
         * @param nioSocket the shared NIOSocket instance
         */
        public Builder nioSocket(NIOSocket nioSocket) {
            this.nioSocket = nioSocket;
            return this;
        }

        public Builder registerEngine(ScanEngine engine) {
            this.customEngines.add(engine);
            return this;
        }

        public NMapScanner build(ExecutorService executorService) {
            NMapConfig config = configBuilder.build();
            NMapScanner scanner = NMapScanner.create(executorService, config, nioSocket);

            // Register custom engines
            for (ScanEngine engine : customEngines) {
                scanner.registerEngine(engine);
            }

            return scanner;
        }
    }
}
