package io.xlogistx.common.http;

import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;

public class SimpleProtoSessionTest {

    @Test
    public void anonymousSessionBasics() throws Exception {
        SimpleProtoSession<String> session = new SimpleProtoSession<>();
        assertNull(session.getSubjectID());
        assertSame(session, session.getSession());
        assertFalse(session.isClosed());
        assertTrue(session.canClose(), "no monitors => closeable");
        assertNotNull(session.getProperties());
        assertSame(session.getProperties(), session.getProperties(), "properties must be created once");
        assertNotNull(session.getAutoCloseables());
        session.close();
        assertTrue(session.isClosed());
    }

    @Test
    public void subjectIDIsRetained() {
        SimpleProtoSession<String> session = new SimpleProtoSession<>("user-1");
        assertEquals("user-1", session.getSubjectID());
    }

    @Test
    public void closeMonitorsGateCanClose() throws Exception {
        AtomicBoolean done = new AtomicBoolean(false);
        Supplier<Boolean> monitor = done::get;
        SimpleProtoSession<String> session = new SimpleProtoSession<>(null, monitor);

        assertFalse(session.canClose());
        done.set(true);
        assertTrue(session.canClose());

        done.set(false);
        assertFalse(session.canClose());
        session.removeCloseMonitor(monitor);
        assertTrue(session.canClose(), "removed monitor no longer vetoes");

        session.addCloseMonitor(monitor);
        assertFalse(session.canClose());
        session.close();
        assertTrue(session.canClose(), "closed session is always closeable regardless of monitors");
    }

    @Test
    public void nullMonitorsAreIgnored() {
        SimpleProtoSession<String> session = new SimpleProtoSession<>(null, null);
        session.addCloseMonitor(null);
        session.removeCloseMonitor(null);
        assertTrue(session.canClose());
    }

    @Test
    public void closeReleasesAutoCloseablesOnce() throws Exception {
        AtomicInteger closed = new AtomicInteger();
        SimpleProtoSession<String> session = new SimpleProtoSession<>();
        session.getAutoCloseables().add(closed::incrementAndGet);
        session.getAutoCloseables().add(closed::incrementAndGet);
        session.getAutoCloseables().add(() -> { throw new IllegalStateException("boom"); });
        session.getAutoCloseables().add(closed::incrementAndGet);

        session.close();
        assertEquals(3, closed.get(), "all closeables closed even if one throws");
        session.close();
        assertEquals(3, closed.get(), "second close is a no-op");
    }

    @Test
    public void attachDetachBindsToCurrentThread() throws Exception {
        SimpleProtoSession<String> session = new SimpleProtoSession<>("s");
        assertNull(SimpleProtoSession.current());
        assertFalse(session.detach(), "detach when not attached is safe and returns false");

        long before = session.getLastAccessTS();
        Thread.sleep(2);
        assertTrue(session.attach());
        assertSame(session, SimpleProtoSession.current());
        assertTrue(session.getLastAccessTS() >= before);

        SimpleProtoSession<String> other = new SimpleProtoSession<>("o");
        assertFalse(other.detach(), "detaching a different session must not unbind ours");
        assertSame(session, SimpleProtoSession.current());

        assertTrue(session.detach());
        assertNull(SimpleProtoSession.current());

        session.attach();
        session.close();
        assertNull(SimpleProtoSession.current(), "close unbinds the session from the thread");
        assertFalse(session.attach(), "closed session cannot be attached");
    }

    @Test
    public void attachIsThreadLocal() throws Exception {
        SimpleProtoSession<String> session = new SimpleProtoSession<>("s");
        session.attach();
        AtomicBoolean seenOnOtherThread = new AtomicBoolean(true);
        Thread t = new Thread(() -> seenOnOtherThread.set(SimpleProtoSession.current() != null));
        t.start();
        t.join();
        assertFalse(seenOnOtherThread.get());
        session.detach();
    }
}
