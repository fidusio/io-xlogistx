package io.xlogistx.shiro;

import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.shared.io.CloseableTypeRunnable;
import org.zoxweb.shared.protocol.ProtoSession;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NamedValue;

import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.Supplier;

public class ShiroSession<V>
        implements ProtoSession<Session, Subject> {

    public final static String ASSOCIATED_SESSION = "associated-session";
    public final static String SHIRO_SESSION = "shiro-session-self";

    private final Subject subject;
    private final NVGenericMap properties = new NVGenericMap("properties");
    private final CloseableTypeRunnable cth;
    private final Supplier<Boolean> canCloseDecisionMaker;
    private final Set<AutoCloseable> autoCloseables = new LinkedHashSet<>();



    public ShiroSession(Subject subject) {
        this(subject, null, null);
    }


    public ShiroSession(Subject subject, V associatedSession) {
        this(subject, associatedSession, null);
    }

    public ShiroSession(Subject subject, V associatedSession, Supplier<Boolean> canCloseDecisionMaker) {
        this.subject = subject;
        if(associatedSession != null)
            this.subject.getSession().setAttribute(ASSOCIATED_SESSION, associatedSession);

        this.subject.getSession().setAttribute(SHIRO_SESSION, this);

        cth = new CloseableTypeRunnable((Runnable) ()-> {
            NamedValue<SubjectSwap> ss = getProperties().getNV(SubjectSwap.SUBJECT_SWAP);
            if(ss != null && ss.getValue() != null)
                ss.getValue().close();
            subject.logout();
            AutoCloseable[] toClose = autoCloseables.toArray(new AutoCloseable[0]);
            IOUtil.close(toClose);
         });
        this.canCloseDecisionMaker = canCloseDecisionMaker;

    }

    /**
     * @return the actual session associated with the implementation
     */
    @Override
    public Session getSession() {
        return subject.getSession();
    }

    /**
     * @return true is the session is closed or the implementation can be closed, it is not mandatory to obied by the response the caller can invoke close regardless
     */
    @Override
    public boolean canClose() {
        if (canCloseDecisionMaker != null)
            return canCloseDecisionMaker.get();
        return true;
    }

    @Override
    public Set<AutoCloseable> getAutoCloseables() {
        return autoCloseables;
    }

    /**
     * Attach the session to the current context like a thread or something else
     *
     * @return true if the session was attached successfully
     */
    @Override
    public boolean attach() {
        ThreadContext.bind(subject);
        if(subject != null)
            subject.getSession().touch();
        return subject != null;
    }

    /**
     * Detach the session from the current context
     *
     * @return true if the session was detached successfully
     */
    @Override
    public boolean detach() {
        return ThreadContext.unbindSubject() != null;
    }

    /**
     * Closes this stream and releases any system resources associated
     * with it. If the stream is already closed then invoking this
     * method has no effect.
     *
     * <p> As noted in {@link AutoCloseable#close()}, cases where the
     * close may fail require careful attention. It is strongly advised
     * to relinquish the underlying resources and to internally
     * <em>mark</em> the {@code Closeable} as closed, prior to throwing
     * the {@code IOException}.
     *
     * @throws IOException if an I/O error occurs
     */
    @Override
    public void close() throws IOException {
        cth.close();
    }

    /**
     * Returns the subject ID.
     *
     * @return the subject of the session
     */
    @Override
    public Subject getSubjectID() {
        return subject;
    }

    @Override
    public NVGenericMap getProperties() {
        return properties;
    }

    /**
     * Checks if closed.
     *
     * @return true if closed
     */
    @Override
    public boolean isClosed() {
        return cth.isClosed();
    }

    /**
     *
     * @return associated app specific session
     */
    public V getAssociatedSession()
    {
        return ShiroUtil.getAssociatedSession(getSession());
    }

}
