package io.xlogistx.common.nmap.discovery;

import io.xlogistx.common.nmap.config.NMapConfig;
import org.zoxweb.server.logging.LogWrapper;

import java.util.*;
import java.util.concurrent.*;

/**
 * Host discovery orchestrator.
 * Runs multiple discovery methods to determine if hosts are up.
 */
public class HostDiscovery {

    public static final LogWrapper log = new LogWrapper(HostDiscovery.class).setEnabled(false);

    private final List<DiscoveryMethod> methods;
    private final ExecutorService executor;

    public HostDiscovery(ExecutorService executor) {
        this.methods = new ArrayList<>();
        this.executor = executor;

        // Register default methods
        methods.add(new TCPPing(executor));
        methods.add(new ICMPPing(executor));
    }

    /**
     * Register a custom discovery method
     */
    public void registerMethod(DiscoveryMethod method) {
        methods.add(method);
    }

    /**
     * Discover if a host is up using all available methods
     */
    public CompletableFuture<DiscoveryResult> discover(String host, NMapConfig config) {
        if (config.isSkipHostDiscovery()) {
            return CompletableFuture.completedFuture(
                DiscoveryResult.up("user-set", "skip", 0)
            );
        }

        // Try each method until one succeeds
        return CompletableFuture.supplyAsync(() -> {
            for (DiscoveryMethod method : methods) {
                // Skip raw socket methods if not available
                if (method.requiresRawSockets()) {
                    continue;
                }

                try {
                    DiscoveryResult result = method.isHostUp(host, config)
                        .get(config.getTimeoutSec(), TimeUnit.SECONDS);

                    if (result.isHostUp()) {
                        return result;
                    }
                } catch (Exception e) {
                    if (log.isEnabled()) {
                        log.getLogger().info("Discovery method " + method.getName() +
                            " failed: " + e.getMessage());
                    }
                }
            }

            // All methods failed
            return DiscoveryResult.down("no-response", "all-methods");
        }, executor);
    }

    /**
     * Discover multiple hosts
     */
    public CompletableFuture<Map<String, DiscoveryResult>> discoverAll(
            List<String> hosts, NMapConfig config) {

        Map<String, CompletableFuture<DiscoveryResult>> futures = new LinkedHashMap<>();

        for (String host : hosts) {
            futures.put(host, discover(host, config));
        }

        return CompletableFuture.supplyAsync(() -> {
            Map<String, DiscoveryResult> results = new LinkedHashMap<>();
            for (Map.Entry<String, CompletableFuture<DiscoveryResult>> entry : futures.entrySet()) {
                try {
                    results.put(entry.getKey(),
                        entry.getValue().get(config.getTimeoutSec() * 2, TimeUnit.SECONDS));
                } catch (Exception e) {
                    results.put(entry.getKey(),
                        DiscoveryResult.down("error: " + e.getMessage(), "error"));
                }
            }
            return results;
        }, executor);
    }

    /**
     * Get hosts that are up
     */
    public CompletableFuture<List<String>> getUpHosts(List<String> hosts, NMapConfig config) {
        return discoverAll(hosts, config).thenApply(results -> {
            List<String> upHosts = new ArrayList<>();
            for (Map.Entry<String, DiscoveryResult> entry : results.entrySet()) {
                if (entry.getValue().isHostUp()) {
                    upHosts.add(entry.getKey());
                }
            }
            return upHosts;
        });
    }

}
