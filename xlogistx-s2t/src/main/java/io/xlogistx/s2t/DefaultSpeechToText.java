package io.xlogistx.s2t;

import io.xlogistx.s2t.audio.AudioSource;

import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.function.Supplier;

/**
 * The one {@link SpeechToText} implementation. Platform independent: everything
 * platform specific sits behind {@link AudioSource} and {@link Transcriber}.
 * <p>
 * Threads:
 * <ul>
 *   <li>the caller's thread runs {@code start}, {@code stop}, {@code cancel},
 *       {@code close}; each only flips state and returns;</li>
 *   <li>one daemon thread per utterance ("s2t-capture") reads the audio source;</li>
 *   <li>the executor passed in runs the transcription and the result callbacks.</li>
 * </ul>
 * {@link #lock} guards {@code state} and {@code capture} only. No listener callback is
 * ever made while holding it. The one slow call made under it is opening the audio
 * source in {@code start()}, so that two concurrent starts cannot both open the device.
 */
final class DefaultSpeechToText implements SpeechToText {

    /** Samples asked of the source per read: 100 ms. */
    private static final int CHUNK = AudioSource.SAMPLE_RATE / 10;

    /** How long {@code close()} waits for the capture thread to notice. */
    private static final long CLOSE_JOIN_MILLIS = 2_000;

    private final Transcriber transcriber;
    private final Supplier<? extends AudioSource> sources;
    private final TranscriptListener listener;
    private final Executor executor;
    private final int maxSamples;

    private final Object lock = new Object();
    private State state = State.IDLE;
    private Capture capture;

    DefaultSpeechToText(Transcriber transcriber,
                        Supplier<? extends AudioSource> sources,
                        TranscriptListener listener,
                        Executor executor,
                        int maxUtteranceSeconds) {
        this.transcriber = Objects.requireNonNull(transcriber, "transcriber");
        this.sources = Objects.requireNonNull(sources, "sources");
        this.listener = Objects.requireNonNull(listener, "listener");
        this.executor = Objects.requireNonNull(executor, "executor");
        if (maxUtteranceSeconds < 1) {
            throw new IllegalArgumentException(
                    "maxUtteranceSeconds must be >= 1, got " + maxUtteranceSeconds);
        }
        this.maxSamples = (int) Math.min(Integer.MAX_VALUE - 8L,
                                         (long) maxUtteranceSeconds * AudioSource.SAMPLE_RATE);
    }

    @Override
    public void start() throws S2TException {
        Capture started;
        synchronized (lock) {
            if (state != State.IDLE) {
                throw new IllegalStateException("start() needs state IDLE, but state is " + state);
            }
            AudioSource source = Objects.requireNonNull(sources.get(), "audio source");
            try {
                source.open();
            } catch (S2TException | RuntimeException e) {
                source.close();
                throw e;
            }
            started = new Capture(source);
            capture = started;
            state = State.LISTENING;
        }
        notifyState(State.LISTENING);
        started.thread.start();
    }

    @Override
    public void stop() {
        synchronized (lock) {
            if (state == State.LISTENING && capture != null) {
                capture.stopRequested = true;
            }
        }
    }

    @Override
    public void cancel() {
        synchronized (lock) {
            if (state == State.LISTENING && capture != null) {
                capture.cancelled = true;
            }
        }
    }

    @Override
    public State state() {
        synchronized (lock) {
            return state;
        }
    }

    @Override
    public void close() {
        Capture running;
        synchronized (lock) {
            if (state == State.CLOSED) {
                return;
            }
            state = State.CLOSED;
            running = capture;
            capture = null;
        }
        if (running != null) {
            running.cancelled = true;
            if (Thread.currentThread() != running.thread) {
                try {
                    running.thread.join(CLOSE_JOIN_MILLIS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
        notifyState(State.CLOSED);
        // Blocks until a running transcription returns: the native context must not be
        // freed underneath it.
        transcriber.close();
    }

    /** One utterance's capture. Owns its audio source from open to close. */
    private final class Capture implements Runnable {

        final AudioSource source;
        final Thread thread;
        volatile boolean stopRequested;
        volatile boolean cancelled;

        Capture(AudioSource source) {
            this.source = source;
            this.thread = new Thread(this, "s2t-capture");
            this.thread.setDaemon(true);
        }

        @Override
        public void run() {
            float[] chunk = new float[CHUNK];
            float[] data = new float[Math.min(maxSamples, AudioSource.SAMPLE_RATE * 10)];
            int size = 0;
            S2TException failure = null;

            try {
                while (!stopRequested && !cancelled && size < maxSamples) {
                    int n = source.read(chunk, 0, Math.min(chunk.length, maxSamples - size));
                    if (n < 0) {
                        break;
                    }
                    if (n == 0) {
                        Thread.onSpinWait();
                        continue;
                    }
                    if (size + n > data.length) {
                        data = Arrays.copyOf(data, (int) Math.min(maxSamples,
                                                                  Math.max(data.length * 2L, size + (long) n)));
                    }
                    System.arraycopy(chunk, 0, data, size, n);
                    size += n;
                }
            } catch (S2TException e) {
                failure = e;
            } catch (RuntimeException e) {
                failure = new S2TException("Audio capture failed: " + e, e);
            } finally {
                source.close();
            }

            captureFinished(this, data, size, failure);
        }
    }

    private void captureFinished(Capture finished, float[] data, int size, S2TException failure) {
        boolean transcribe;
        synchronized (lock) {
            if (capture != finished || state == State.CLOSED) {
                return;                     // closed while capturing: drop everything
            }
            capture = null;
            transcribe = failure == null && !finished.cancelled;
            state = transcribe ? State.TRANSCRIBING : State.IDLE;
        }

        if (!transcribe) {
            notifyState(State.IDLE);
            if (failure != null) {
                notifyError(failure);
            }
            return;
        }

        notifyState(State.TRANSCRIBING);
        try {
            executor.execute(() -> transcribe(data, size));
        } catch (RejectedExecutionException e) {
            if (backToIdle()) {
                notifyError(new S2TException("The executor rejected the transcription task", e));
            }
        }
    }

    private void transcribe(float[] data, int size) {
        Transcript result = null;
        S2TException failure = null;
        try {
            long started = System.nanoTime();
            String text = size == 0 ? "" : transcriber.transcribe(data, 0, size);
            long inferenceMillis = (System.nanoTime() - started) / 1_000_000;
            result = new Transcript(text, size * 1000L / AudioSource.SAMPLE_RATE, inferenceMillis);
        } catch (S2TException e) {
            failure = e;
        } catch (RuntimeException e) {
            failure = new S2TException("Transcription failed: " + e, e);
        }

        // IDLE before the callback, so a listener may call start() from inside it.
        if (!backToIdle()) {
            return;                         // closed meanwhile: the result is dropped
        }
        if (result != null) {
            try {
                listener.onTranscript(result);
            } catch (RuntimeException ignored) {
                // A faulty listener must not take the executor thread down.
            }
        } else {
            notifyError(failure);
        }
    }

    /** @return false when the session was closed, in which case nothing was changed or notified */
    private boolean backToIdle() {
        synchronized (lock) {
            if (state == State.CLOSED) {
                return false;
            }
            state = State.IDLE;
        }
        notifyState(State.IDLE);
        return true;
    }

    private void notifyState(State newState) {
        try {
            listener.onStateChange(newState);
        } catch (RuntimeException ignored) {
            // see TranscriptListener: callbacks cannot break the session
        }
    }

    private void notifyError(S2TException error) {
        try {
            listener.onError(error);
        } catch (RuntimeException ignored) {
            // see TranscriptListener
        }
    }
}
