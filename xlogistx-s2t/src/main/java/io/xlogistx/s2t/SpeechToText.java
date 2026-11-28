package io.xlogistx.s2t;

/**
 * A listening session: an audio source, a {@link Transcriber} and a
 * {@link TranscriptListener} joined into start / stop.
 *
 * <pre>
 *   IDLE --start()--> LISTENING --stop()--> TRANSCRIBING --(listener called)--> IDLE
 *                         |
 *                         +--cancel()--> IDLE          (audio discarded, no callback)
 *
 *   any state --close()--> CLOSED
 * </pre>
 *
 * One utterance at a time. Listening also ends by itself when the utterance reaches
 * {@link S2TConfig#maxUtteranceSeconds()}, exactly as if {@code stop()} had been called.
 * <p>
 * All methods return at once and may be called from any thread, including the Swing
 * event thread; capture and transcription run elsewhere.
 */
public interface SpeechToText extends AutoCloseable {

    enum State {
        /** Ready for {@link #start()}. */
        IDLE,
        /** The audio source is open and samples are being collected. */
        LISTENING,
        /** Capture has ended and the engine is working on the audio. */
        TRANSCRIBING,
        /** {@link #close()} was called. Terminal. */
        CLOSED
    }

    /**
     * Opens the audio source and begins collecting samples.
     *
     * @throws S2TException          when the audio source cannot be opened (no
     *                               microphone, access denied); the session stays IDLE
     * @throws IllegalStateException unless the session is IDLE
     */
    void start() throws S2TException;

    /**
     * Ends capture and hands the audio to the engine. The result arrives on the
     * listener. Does nothing unless the session is LISTENING.
     */
    void stop();

    /** Ends capture and discards the audio. Does nothing unless the session is LISTENING. */
    void cancel();

    State state();

    /**
     * Ends the session and closes its {@link Transcriber}. Waits for a running
     * transcription to finish, whose result is then dropped. Idempotent.
     */
    @Override
    void close();
}
