package io.xlogistx.shiro;

import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.zoxweb.shared.protocol.ProtoSession;
import org.zoxweb.shared.util.CloseableTypeHolder;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NamedValue;

import java.io.IOException;
import java.util.function.Supplier;

public class ShiroSession
        implements ProtoSession<Session, Subject> {

    private final Session session;
    private final Subject subject;
    private final NVGenericMap properties = new NVGenericMap("properties");
    private final CloseableTypeHolder cth;
    private final Supplier<Boolean> canCloseDecisionMaker;

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
     * @return
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
     * @param id
     */
    @Override
    public void setSubjectID(Subject id) {
        throw new IllegalArgumentException("Method not allowed");
    }
}
