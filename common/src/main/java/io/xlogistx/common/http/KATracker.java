package io.xlogistx.common.http;

import org.zoxweb.shared.util.UsageTracker;

import java.io.Closeable;

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


    /**
     * Closes this resource, relinquishing any underlying resources.
     * This method is invoked automatically on objects managed by the
     * {@code try}-with-resources statement.
     *
     * @throws Exception if this resource cannot be closed
     * @apiNote While this interface method is declared to throw {@code
     * Exception}, implementers are <em>strongly</em> encouraged to
     * declare concrete implementations of the {@code close} method to
     * throw more specific exceptions, or to throw no exception at all
     * if the close operation cannot fail.
     *
     * <p> Cases where the close operation may fail require careful
     * attention by implementers. It is strongly advised to relinquish
     * the underlying resources and to internally <em>mark</em> the
     * resource as closed, prior to throwing the exception. The {@code
     * close} method is unlikely to be invoked more than once and so
     * this ensures that the resources are released in a timely manner.
     * Furthermore it reduces problems that could arise when the resource
     * wraps, or is wrapped, by another resource.
     *
     * <p><em>Implementers of this interface are also strongly advised
     * to not have the {@code close} method throw {@link
     * InterruptedException}.</em>
     * <p>
     * This exception interacts with a thread's interrupted status,
     * and runtime misbehavior is likely to occur if an {@code
     * InterruptedException} is {@linkplain Throwable#addSuppressed
     * suppressed}.
     * <p>
     * More generally, if it would cause problems for an
     * exception to be suppressed, the {@code AutoCloseable.close}
     * method should not throw it.
     *
     * <p>Note that unlike the {@link Closeable#close close}
     * method of {@link Closeable}, this {@code close} method
     * is <em>not</em> required to be idempotent.  In other words,
     * calling this {@code close} method more than once may have some
     * visible side effect, unlike {@code Closeable.close} which is
     * required to have no effect if called more than once.
     * <p>
     * However, implementers of this interface are strongly encouraged
     * to make their {@code close} methods idempotent.
     */
    @Override
    public void close() {
        expire();
    }
}
