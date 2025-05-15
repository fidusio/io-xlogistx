package io.xlogistx.common.http;

import org.zoxweb.shared.util.UsageTracker;

public class KATracker
        implements UsageTracker {

    public final KAConfig kaConfig;
    private volatile int counter = 0;
    private volatile long lastUpdateTS = 0;
    private final HTTPProtocolHandler hph;
    private boolean expired = false;

    public KATracker(KAConfig kaConfig, HTTPProtocolHandler hph) {
        this.kaConfig = kaConfig;
        this.hph = hph;
    }


    /**
     * @return last time used
     */
    @Override
    public long lastUsage() {
        return counter;
    }

    /**
     * @return current usage update
     */
    @Override
    public synchronized long updateUsage() {
        if (isExpired())
            throw new UnsupportedOperationException("max=" + (kaConfig != null ? kaConfig.max : " KAConfig null ") + " reached");

        lastUpdateTS = System.currentTimeMillis();
        return counter++;
    }

    @Override
    public synchronized long updateUsage(long usage) {
        if (isExpired())
            throw new UnsupportedOperationException("max=" + (kaConfig != null ? kaConfig.max : " KAConfig null ") + " reached");

        lastUpdateTS = System.currentTimeMillis();
        return counter++;
    }


    @Override
    public synchronized void expire() {
        expired = true;
    }

    @Override
    public synchronized boolean isExpired() {
        if (expired)
            return true;

        // check if hph is closed or kaConfig is null and we http protocol
        if (kaConfig == null && hph.isHTTPProtocol())
            return true;

        // if it is a websocket never expire
        // kaConfig == null is ok
        if (hph.isWSProtocol())
            return false;


        // check time stamp expiry
        // at this level we are http protocol and kaConfig is not null
        if (kaConfig.time_out > 0 && lastUpdateTS != 0) {
            if (lastUsage() > 0 && System.currentTimeMillis() - lastUpdateTS > kaConfig.time_out)
                return true;
        }
        // we did not expire with timeout check mas usage
        return (kaConfig.max != 0 && kaConfig.max == counter);
    }
}
