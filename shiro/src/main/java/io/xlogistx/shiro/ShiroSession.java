package io.xlogistx.shiro;

import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.shared.protocol.ProtoSession;
import org.zoxweb.shared.util.CloseableTypeHolder;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NamedValue;

import java.io.Closeable;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Supplier;

public class ShiroSession
        implements ProtoSession<Session, Subject> {

    private final Session session;
    private final Subject subject;
    private final NVGenericMap properties = new NVGenericMap("properties");
    private final CloseableTypeHolder cth;
    private final Supplier<Boolean> canCloseDecisionMaker;
    private final Set<AutoCloseable> associated = new HashSet<>();

    public ShiroSession(Subject subject) {
        this(subject, null);
    }

    public ShiroSession(Subject subject, Supplier<Boolean> canCloseDecisionMaker) {
        this.subject = subject;
        session = subject.getSession();
        cth = new CloseableTypeHolder((Runnable) ()-> {
            NamedValue<SubjectSwap> ss = getProperties().getNV(SubjectSwap.SUBJECT_SWAP);
            if(ss != null && ss.getValue() != null)
                ss.getValue().close();
            session.stop();
            subject.logout();
            IOUtil.close(associated.toArray(new Closeable[0]));
         });
        this.canCloseDecisionMaker = canCloseDecisionMaker;

    }

    /**
     * @return the actual session associated with the implementation
     */
    @Override
    public Session getSession() {
        return session;
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
    public Set<AutoCloseable> getAssociated() {
        return associated;
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
     * Sets the subject ID.
     *
     * @param subject the subject of hte session
     */
    @Override
    public void setSubjectID(Subject subject) {
        throw new IllegalArgumentException("Method not allowed");
    }
}
