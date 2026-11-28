package io.xlogistx.s2t;

import io.xlogistx.s2t.audio.AudioSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The session's state machine, driven with a fake microphone and a fake engine: no
 * audio device, no native library, runs anywhere.
 */
@Timeout(20)
class DefaultSpeechToTextTest {

    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    @AfterEach
    void shutdown() {
        executor.shutdownNow();
    }

    /** Produces 10 ms of audio per read, forever, until closed. */
    private static final class FakeSource implements AudioSource {
        final AtomicInteger opened = new AtomicInteger();
        final AtomicInteger closed = new AtomicInteger();
        volatile S2TException openFailure;
        volatile S2TException readFailure;

        @Override
        public void open() throws S2TException {
            if (openFailure != null) {
                throw openFailure;
            }
            opened.incrementAndGet();
        }

        @Override
        public int read(float[] buffer, int offset, int length) throws S2TException {
            if (readFailure != null) {
                throw readFailure;
            }
            try {
                Thread.sleep(2);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return -1;
            }
            int n = Math.min(length, 160);
            for (int i = 0; i < n; i++) {
                buffer[offset + i] = 0.25f;
            }
            return n;
        }

        @Override
        public void close() {
            closed.incrementAndGet();
        }
    }

    /** Reports how many samples it was given. */
    private static final class FakeTranscriber implements Transcriber {
        final AtomicInteger closed = new AtomicInteger();
        volatile S2TException failure;
        volatile CountDownLatch gate;

        @Override
        public String transcribe(float[] samples, int offset, int length) throws S2TException {
            CountDownLatch g = gate;
            if (g != null) {
                try {
                    g.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            if (failure != null) {
                throw failure;
            }
            return "samples=" + length;
        }

        @Override
        public void close() {
            closed.incrementAndGet();
        }
    }

    private static final class Recorder implements TranscriptListener {
        final List<Transcript> transcripts = new CopyOnWriteArrayList<>();
        final List<S2TException> errors = new CopyOnWriteArrayList<>();
        final List<SpeechToText.State> states = new CopyOnWriteArrayList<>();
        volatile CountDownLatch outcome = new CountDownLatch(1);

        @Override
        public void onTranscript(Transcript transcript) {
            transcripts.add(transcript);
            outcome.countDown();
        }

        @Override
        public void onError(S2TException error) {
            errors.add(error);
            outcome.countDown();
        }

        @Override
        public void onStateChange(SpeechToText.State state) {
            states.add(state);
        }

        void awaitOutcome() throws InterruptedException {
            assertTrue(outcome.await(10, TimeUnit.SECONDS), "no transcript or error arrived");
        }
    }

    private static void awaitState(SpeechToText stt, SpeechToText.State wanted) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (stt.state() != wanted) {
            assertTrue(System.nanoTime() < deadline, "state stayed " + stt.state() + ", wanted " + wanted);
            Thread.sleep(5);
        }
    }

    @Test
    void startThenStopDeliversOneTranscriptAndReturnsToIdle() throws Exception {
        FakeSource source = new FakeSource();
        FakeTranscriber transcriber = new FakeTranscriber();
        Recorder recorder = new Recorder();
        SpeechToText stt = SpeechToTextFactory.create(transcriber, () -> source, recorder, executor, 60);

        assertEquals(SpeechToText.State.IDLE, stt.state());
        stt.start();
        assertEquals(SpeechToText.State.LISTENING, stt.state());
        Thread.sleep(60);
        stt.stop();
        recorder.awaitOutcome();

        assertEquals(1, recorder.transcripts.size());
        assertTrue(recorder.errors.isEmpty());
        Transcript transcript = recorder.transcripts.get(0);
        assertTrue(transcript.text().startsWith("samples="), transcript.text());
        assertTrue(transcript.audioMillis() > 0);
        assertEquals(SpeechToText.State.IDLE, stt.state());
        assertEquals(List.of(SpeechToText.State.LISTENING, SpeechToText.State.TRANSCRIBING,
                             SpeechToText.State.IDLE), recorder.states);
        assertEquals(1, source.opened.get());
        assertEquals(1, source.closed.get());

        stt.close();
        assertEquals(SpeechToText.State.CLOSED, stt.state());
        assertEquals(1, transcriber.closed.get());
    }

    @Test
    void theSessionCanBeUsedForSeveralUtterances() throws Exception {
        FakeSource source = new FakeSource();
        Recorder recorder = new Recorder();
        try (SpeechToText stt = SpeechToTextFactory.create(new FakeTranscriber(), () -> source,
                                                          recorder, executor, 60)) {
            for (int i = 0; i < 3; i++) {
                recorder.outcome = new CountDownLatch(1);
                stt.start();
                Thread.sleep(20);
                stt.stop();
                recorder.awaitOutcome();
                awaitState(stt, SpeechToText.State.IDLE);
            }
        }
        assertEquals(3, recorder.transcripts.size());
        assertEquals(3, source.opened.get());
        assertEquals(3, source.closed.get());
    }

    @Test
    void cancelDiscardsTheAudioAndCallsNoResultCallback() throws Exception {
        FakeSource source = new FakeSource();
        Recorder recorder = new Recorder();
        try (SpeechToText stt = SpeechToTextFactory.create(new FakeTranscriber(), () -> source,
                                                          recorder, executor, 60)) {
            stt.start();
            Thread.sleep(30);
            stt.cancel();
            awaitState(stt, SpeechToText.State.IDLE);

            assertFalse(recorder.outcome.await(150, TimeUnit.MILLISECONDS));
            assertTrue(recorder.transcripts.isEmpty());
            assertTrue(recorder.errors.isEmpty());
            assertEquals(1, source.closed.get());
        }
    }

    @Test
    void listeningStopsByItselfAtTheMaximumLength() throws Exception {
        FakeSource source = new FakeSource();
        Recorder recorder = new Recorder();
        // 1 second maximum = 16,000 samples = 100 reads of 160 samples.
        try (SpeechToText stt = SpeechToTextFactory.create(new FakeTranscriber(), () -> source,
                                                          recorder, executor, 1)) {
            stt.start();
            recorder.awaitOutcome();
            assertEquals("samples=16000", recorder.transcripts.get(0).text());
            assertEquals(1000, recorder.transcripts.get(0).audioMillis());
        }
    }

    @Test
    void startWhileListeningOrAfterCloseIsRejected() throws Exception {
        FakeSource source = new FakeSource();
        SpeechToText stt = SpeechToTextFactory.create(new FakeTranscriber(), () -> source,
                                                     new Recorder(), executor, 60);
        stt.start();
        assertThrows(IllegalStateException.class, stt::start);
        stt.close();
        assertThrows(IllegalStateException.class, stt::start);
        stt.close();                                    // idempotent
        stt.stop();                                     // harmless when closed
        stt.cancel();
        assertEquals(SpeechToText.State.CLOSED, stt.state());
    }

    @Test
    void aSourceThatCannotOpenLeavesTheSessionIdle() {
        FakeSource source = new FakeSource();
        source.openFailure = new S2TException("no microphone");
        try (SpeechToText stt = SpeechToTextFactory.create(new FakeTranscriber(), () -> source,
                                                          new Recorder(), executor, 60)) {
            S2TException e = assertThrows(S2TException.class, stt::start);
            assertEquals("no microphone", e.getMessage());
            assertEquals(SpeechToText.State.IDLE, stt.state());
            assertEquals(1, source.closed.get());
        }
    }

    @Test
    void aCaptureFailureIsReportedAndTheSessionRecovers() throws Exception {
        FakeSource source = new FakeSource();
        source.readFailure = new S2TException("device unplugged");
        Recorder recorder = new Recorder();
        try (SpeechToText stt = SpeechToTextFactory.create(new FakeTranscriber(), () -> source,
                                                          recorder, executor, 60)) {
            stt.start();
            recorder.awaitOutcome();
            assertEquals("device unplugged", recorder.errors.get(0).getMessage());
            awaitState(stt, SpeechToText.State.IDLE);

            source.readFailure = null;
            recorder.outcome = new CountDownLatch(1);
            stt.start();
            Thread.sleep(20);
            stt.stop();
            recorder.awaitOutcome();
            assertEquals(1, recorder.transcripts.size());
        }
    }

    @Test
    void anEngineFailureIsReportedThroughOnError() throws Exception {
        FakeTranscriber transcriber = new FakeTranscriber();
        transcriber.failure = new S2TException("engine failed with code 7");
        Recorder recorder = new Recorder();
        try (SpeechToText stt = SpeechToTextFactory.create(transcriber, FakeSource::new,
                                                          recorder, executor, 60)) {
            stt.start();
            Thread.sleep(20);
            stt.stop();
            recorder.awaitOutcome();
            assertEquals("engine failed with code 7", recorder.errors.get(0).getMessage());
            assertTrue(recorder.transcripts.isEmpty());
            awaitState(stt, SpeechToText.State.IDLE);
        }
    }

    @Test
    void closingDuringTranscriptionDropsTheResult() throws Exception {
        FakeTranscriber transcriber = new FakeTranscriber();
        transcriber.gate = new CountDownLatch(1);
        Recorder recorder = new Recorder();
        SpeechToText stt = SpeechToTextFactory.create(transcriber, FakeSource::new, recorder, executor, 60);

        stt.start();
        Thread.sleep(20);
        stt.stop();
        awaitState(stt, SpeechToText.State.TRANSCRIBING);

        stt.close();                    // the fake's close() does not block, unlike the real engine's
        transcriber.gate.countDown();   // let the in-flight transcription return

        assertFalse(recorder.outcome.await(200, TimeUnit.MILLISECONDS));
        assertTrue(recorder.transcripts.isEmpty());
        assertEquals(SpeechToText.State.CLOSED, stt.state());
    }

    @Test
    void aListenerThatThrowsDoesNotBreakTheSession() throws Exception {
        CountDownLatch delivered = new CountDownLatch(2);
        TranscriptListener faulty = new TranscriptListener() {
            @Override
            public void onTranscript(Transcript transcript) {
                delivered.countDown();
                throw new IllegalStateException("listener bug");
            }

            @Override
            public void onError(S2TException error) {
            }

            @Override
            public void onStateChange(SpeechToText.State state) {
                throw new IllegalStateException("listener bug");
            }
        };
        try (SpeechToText stt = SpeechToTextFactory.create(new FakeTranscriber(), FakeSource::new,
                                                          faulty, executor, 60)) {
            for (int i = 0; i < 2; i++) {
                stt.start();
                Thread.sleep(20);
                stt.stop();
                awaitState(stt, SpeechToText.State.IDLE);
            }
            assertTrue(delivered.await(10, TimeUnit.SECONDS));
        }
    }
}
