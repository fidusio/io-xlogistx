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

        // Register default methods - ARP first for local networks
        methods.add(new ARPPing(executor));
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
     * Discover multiple hosts using batch ARP discovery for efficiency.
     * First does batch ARP trigger, then falls back to individual methods.
     */
    public CompletableFuture<Map<String, DiscoveryResult>> discoverAll(
            List<String> hosts, NMapConfig config) {

        // Skip host discovery if configured
        if (config.isSkipHostDiscovery()) {
            Map<String, DiscoveryResult> results = new LinkedHashMap<>();
            for (String host : hosts) {
                results.put(host, DiscoveryResult.up("user-set", "skip", 0));
            }
            return CompletableFuture.completedFuture(results);
        }

        // Use batch ARP discovery for efficiency
        return CompletableFuture.supplyAsync(() -> {
            Map<String, DiscoveryResult> results = new LinkedHashMap<>();

            // Step 1: Batch ARP discovery for all hosts
            ARPPing arpPing = null;
            for (DiscoveryMethod method : methods) {
                if (method instanceof ARPPing) {
                    arpPing = (ARPPing) method;
                    break;
                }
            }

            Set<String> hostsFoundByArp = new HashSet<>();
            if (arpPing != null) {
                try {
                    Map<String, DiscoveryResult> arpResults = arpPing.batchDiscover(hosts, config)
                        .get(config.getTimeoutSec() * 2, TimeUnit.SECONDS);

                    for (Map.Entry<String, DiscoveryResult> entry : arpResults.entrySet()) {
                        if (entry.getValue().isHostUp()) {
                            results.put(entry.getKey(), entry.getValue());
                            hostsFoundByArp.add(entry.getKey());
                        }
                    }
                } catch (Exception e) {
                    if (log.isEnabled()) {
                        log.getLogger().info("Batch ARP discovery failed: " + e.getMessage());
                    }
                }
            }

            // Step 2: For hosts not found by ARP, try other methods in parallel
            List<String> remainingHosts = new ArrayList<>();
            for (String host : hosts) {
                if (!hostsFoundByArp.contains(host)) {
                    remainingHosts.add(host);
                }
            }

            if (!remainingHosts.isEmpty()) {
                Map<String, CompletableFuture<DiscoveryResult>> futures = new LinkedHashMap<>();
                for (String host : remainingHosts) {
                    futures.put(host, discover(host, config));
                }

                for (Map.Entry<String, CompletableFuture<DiscoveryResult>> entry : futures.entrySet()) {
                    try {
                        DiscoveryResult result = entry.getValue().get(config.getTimeoutSec(), TimeUnit.SECONDS);
                        results.put(entry.getKey(), result);
                    } catch (Exception e) {
                        results.put(entry.getKey(),
                            DiscoveryResult.down("error: " + e.getMessage(), "error"));
                    }
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
