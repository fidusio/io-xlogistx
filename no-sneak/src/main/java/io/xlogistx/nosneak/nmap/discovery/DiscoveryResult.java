package io.xlogistx.nosneak.nmap.discovery;

/**
 * Result of a host discovery attempt.
 */
public class DiscoveryResult {

    private final boolean hostUp;
    private final String reason;
    private final String method;
    private final long latencyMs;
    private final int ttl;

    private DiscoveryResult(boolean hostUp, String reason, String method, long latencyMs, int ttl) {
        this.hostUp = hostUp;
        this.reason = reason;
        this.method = method;
        this.latencyMs = latencyMs;
        this.ttl = ttl;
    }

    public boolean isHostUp() {
        return hostUp;
    }

    public String getReason() {
        return reason;
    }

    public String getMethod() {
        return method;
    }

    public long getLatencyMs() {
        return latencyMs;
    }

    public int getTtl() {
        return ttl;
    }

    public static DiscoveryResult up(String reason, String method, long latencyMs) {
        return new DiscoveryResult(true, reason, method, latencyMs, -1);
    }

    public static DiscoveryResult up(String reason, String method, long latencyMs, int ttl) {
        return new DiscoveryResult(true, reason, method, latencyMs, ttl);
    }

    public static DiscoveryResult down(String reason, String method) {
        return new DiscoveryResult(false, reason, method, -1, -1);
    }

    @Override
    public String toString() {
        if (hostUp) {
            return "Host is up (" + reason + ") via " + method +
                   (latencyMs >= 0 ? " [" + latencyMs + "ms]" : "");
        }
        return "Host is down (" + reason + ")";
    }
}
