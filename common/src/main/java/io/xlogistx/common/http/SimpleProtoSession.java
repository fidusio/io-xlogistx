package io.xlogistx.common.http;

import org.zoxweb.shared.io.CloseableTypeDelegate;
import org.zoxweb.shared.io.SharedIOUtil;
import org.zoxweb.shared.protocol.ProtoSession;
import org.zoxweb.shared.util.CollectionAsArray;
import org.zoxweb.shared.util.LazyValue;
import org.zoxweb.shared.util.NVGenericMap;

import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.Supplier;

/**
 * A lightweight, security-framework-agnostic {@link ProtoSession}.
 *
 * <p>Unlike a Shiro-backed session, this implementation does not create or touch any
 * external session store: the session object it wraps is <em>itself</em>
 * ({@link #getSession()} returns {@code this}), and the subject ID is an optional,
 * caller-supplied value that may be {@code null} for anonymous connections.
 *
 * <p>It provides the full lifecycle contract of {@link ProtoSession}: a lazily created
 * property bag, close monitors that gate {@link #canClose()}, a live set of
 * {@link AutoCloseable} resources released on {@link #close()}, and
 * {@link #attach()}/{@link #detach()} which bind the session to the current thread so
 * it can be resolved implicitly via {@link #current()}.
 *
 * <p>Typical use: a per-connection session for unauthenticated chunked uploads or
 * other transports that need close monitors and resource ownership but no
 * authenticated subject.
 *
 * @param <T> the subject identifier type
 */
public class SimpleProtoSession<T>
        implements ProtoSession<SimpleProtoSession<T>, T> {

    private static final ThreadLocal<SimpleProtoSession<?>> CURRENT = new ThreadLocal<>();

    private final T subjectID;
    private final long creationTS = System.currentTimeMillis();
    private volatile long lastAccessTS = creationTS;
    private final LazyValue<NVGenericMap> properties = new LazyValue<>(this, () -> new NVGenericMap("properties"));
    private final LazyValue<CollectionAsArray<Supplier<Boolean>>> closeDecisionMakers = new LazyValue<>(this, () -> new CollectionAsArray<Supplier<Boolean>>(new LinkedHashSet<>(), new Supplier[0]));
    private final Set<AutoCloseable> autoCloseables = new LinkedHashSet<>();
    private final CloseableTypeDelegate ctd;

    public SimpleProtoSession() {
        this(null, null);
    }

    public SimpleProtoSession(T subjectID) {
        this(subjectID, null);
    }

    /**
     * @param subjectID            optional subject identifier, may be {@code null} for anonymous sessions
     * @param canCloseDecisionMaker optional initial close monitor, {@code null} is ignored
     */
    public SimpleProtoSession(T subjectID, Supplier<Boolean> canCloseDecisionMaker) {
        this.subjectID = subjectID;
        ctd = new CloseableTypeDelegate(() -> {
            AutoCloseable[] toClose;
            synchronized (autoCloseables) {
                toClose = autoCloseables.toArray(new AutoCloseable[0]);
            }
            SharedIOUtil.close(toClose);
            if (CURRENT.get() == this)
                CURRENT.remove();
        }, false);
        addCloseMonitor(canCloseDecisionMaker);
    }

    /**
     * @return the session bound to the current thread via {@link #attach()}, or {@code null}
     */
    @SuppressWarnings("unchecked")
    public static <T> SimpleProtoSession<T> current() {
        return (SimpleProtoSession<T>) CURRENT.get();
    }

    /**
     * @return this instance; the session object is the implementation itself
     */
    @Override
    public SimpleProtoSession<T> getSession() {
        return this;
    }

    @Override
    public T getSubjectID() {
        return subjectID;
    }

    @Override
    public NVGenericMap getProperties() {
        return properties.get();
    }

    @Override
    public boolean canClose() {
        if (isClosed())
            return true;

        if (closeDecisionMakers.isInitialized()) {
            for (Supplier<Boolean> toCheck : closeDecisionMakers.get().asArray())
                if (!toCheck.get())
                    return false;
        }

        return true;
    }

    @Override
    public Set<AutoCloseable> getAutoCloseables() {
        return autoCloseables;
    }

    @Override
    public void addCloseMonitor(Supplier<Boolean> closeMonitor) {
        if (closeMonitor != null)
            closeDecisionMakers.get().add(closeMonitor);
    }

    @Override
    public void removeCloseMonitor(Supplier<Boolean> closeMonitor) {
        if (closeMonitor != null && closeDecisionMakers.isInitialized())
            closeDecisionMakers.get().remove(closeMonitor);
    }

    /**
     * Binds this session to the current thread and refreshes its last-access time.
     *
     * @return {@code true} unless the session is already closed
     */
    @Override
    public boolean attach() {
        if (isClosed())
            return false;
        touch();
        CURRENT.set(this);
        return true;
    }

    /**
     * Unbinds this session from the current thread.
     *
     * @return {@code true} if this session was the one bound to the current thread
     */
    @Override
    public boolean detach() {
        if (CURRENT.get() == this) {
            CURRENT.remove();
            return true;
        }
        return false;
    }

    @Override
    public void close() throws IOException {
        ctd.close();
    }

    @Override
    public boolean isClosed() {
        return ctd.isClosed();
    }

    /**
     * Refreshes the last-access timestamp.
     */
    public void touch() {
        lastAccessTS = System.currentTimeMillis();
    }

    public long getCreationTS() {
        return creationTS;
    }

    public long getLastAccessTS() {
        return lastAccessTS;
    }

    @Override
    public String toString() {
        return "SimpleProtoSession{" +
                "subjectID=" + subjectID +
                ", closed=" + isClosed() +
                ", creationTS=" + creationTS +
                ", lastAccessTS=" + lastAccessTS +
                '}';
    }
}
