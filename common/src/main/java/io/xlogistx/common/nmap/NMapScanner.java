package io.xlogistx.common.nmap;

import io.xlogistx.common.nmap.config.NMapConfig;
import io.xlogistx.common.nmap.config.PortSpecification;
import io.xlogistx.common.nmap.config.TargetSpecification;
import io.xlogistx.common.nmap.config.TimingTemplate;
import io.xlogistx.common.nmap.output.OutputFormat;
import io.xlogistx.common.nmap.output.ScanReport;
import io.xlogistx.common.nmap.scan.*;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.NIOSocket;

import java.io.Closeable;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.*;

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
    private volatile boolean running = false;
    private volatile boolean closed = false;

    private NMapScanner(NMapConfig config) {
        this.config = config;
        this.engines = new EnumMap<>(ScanType.class);
        this.executor = Executors.newFixedThreadPool(
            Math.max(4, config.getMaxParallelism() / 10),
            r -> {
                Thread t = new Thread(r, "NMapScanner-Worker");
                t.setDaemon(true);
                return t;
            }
        );
    }

    /**
     * Create a scanner with the given configuration
     */
    public static NMapScanner create(NMapConfig config) {
        return new NMapScanner(config);
    }

    /**
     * Create a scanner with custom NIOSocket (for backwards compatibility).
     * Note: NIOSocket is not used by scan engines, they use pure Java NIO.
     */
    public static NMapScanner create(NMapConfig config, NIOSocket nioSocket) {
        // NIOSocket is ignored - scan engines use pure Java NIO
        return new NMapScanner(config);
    }

    /**
     * Register a scan engine for a specific scan type
     */
    public NMapScanner registerEngine(ScanEngine engine) {
        // Pass null for NIOSocket since engines use pure Java NIO internally
        engine.init(null, config);
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
     * Perform the scan asynchronously.
     */
    public CompletableFuture<ScanReport> scanAsync() {
        if (closed) {
            CompletableFuture<ScanReport> future = new CompletableFuture<>();
            future.completeExceptionally(new IllegalStateException("Scanner is closed"));
            return future;
        }

        if (running) {
            CompletableFuture<ScanReport> future = new CompletableFuture<>();
            future.completeExceptionally(new IllegalStateException("Scan already in progress"));
            return future;
        }

        running = true;
        long startTime = System.currentTimeMillis();

        return CompletableFuture.supplyAsync(() -> {
            try {
                List<ScanResult> results = new ArrayList<>();
                TargetSpecification targets = config.getTargets();
                PortSpecification ports = config.getPorts();

                // Get the primary scan engine
                ScanType primaryType = config.getPrimaryScanType();
                ScanEngine engine = engines.get(primaryType);

                if (engine == null) {
                    throw new IllegalStateException(
                        "No engine registered for scan type: " + primaryType
                    );
                }

                if (!engine.isAvailable()) {
                    log.getLogger().warning("Engine not available: " + primaryType +
                        ", falling back to TCP_CONNECT");
                    engine = engines.get(ScanType.TCP_CONNECT);
                    if (engine == null) {
                        throw new IllegalStateException("No fallback engine available");
                    }
                }

                // Scan each target
                List<CompletableFuture<ScanResult>> futures = new ArrayList<>();

                for (String target : targets.getTargets()) {
                    List<Integer> portsToScan = getPortsForEngine(engine);

                    if (log.isEnabled()) {
                        log.getLogger().info("Scanning " + target +
                            " with " + portsToScan.size() + " ports");
                    }

                    CompletableFuture<ScanResult> future = engine.scanHost(target, portsToScan);
                    futures.add(future);

                    // Rate limiting based on timing template
                    if (config.getTiming().getProbeDelayMs() > 0) {
                        Thread.sleep(config.getTiming().getProbeDelayMs());
                    }
                }

                // Wait for all scans to complete
                CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

                // Collect results
                for (CompletableFuture<ScanResult> future : futures) {
                    try {
                        results.add(future.get());
                    } catch (Exception e) {
                        log.getLogger().warning("Failed to get scan result: " + e.getMessage());
                    }
                }

                long endTime = System.currentTimeMillis();

                // Build report
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

            } catch (Exception e) {
                throw new CompletionException(e);
            } finally {
                running = false;
            }
        }, executor);
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
            engine.stop();
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
        return closed;
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
        if (closed) return;
        closed = true;

        stop();

        // Close all engines
        for (ScanEngine engine : engines.values()) {
            try {
                engine.close();
            } catch (Exception e) {
                log.getLogger().warning("Error closing engine: " + e.getMessage());
            }
        }

        // Shutdown executor
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Builder for creating NMapScanner instances
     */
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private NMapConfig.Builder configBuilder = NMapConfig.builder();
        private List<ScanEngine> customEngines = new ArrayList<>();

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
         * @deprecated NIOSocket is no longer used. Scan engines use pure Java NIO.
         */
        @Deprecated
        public Builder nioSocket(NIOSocket socket) {
            // Ignored - scan engines use pure Java NIO
            return this;
        }

        public Builder registerEngine(ScanEngine engine) {
            this.customEngines.add(engine);
            return this;
        }

        public NMapScanner build() {
            NMapConfig config = configBuilder.build();
            NMapScanner scanner = NMapScanner.create(config);

            // Register custom engines
            for (ScanEngine engine : customEngines) {
                scanner.registerEngine(engine);
            }

            return scanner;
        }
    }
}
