package io.xlogistx.s2t;

/**
 * Receives the outcome of each utterance from a {@link SpeechToText} session.
 * <p>
 * {@link #onTranscript} and transcription errors arrive on the executor given to
 * {@link SpeechToTextFactory}; capture errors and state changes can also arrive on the
 * session's capture thread or on the thread that called {@code start()}, {@code stop()},
 * {@code cancel()} or {@code close()}. None of these is the Swing event thread: a Swing
 * consumer hops with {@code SwingUtilities.invokeLater}.
 * <p>
 * An exception thrown from a callback is swallowed, so a faulty listener cannot stop
 * the session.
 */
public interface TranscriptListener {

    /** One utterance was transcribed. The session is already back in {@code IDLE}. */
    void onTranscript(Transcript transcript);

    /** Capture or transcription failed. The session is back in {@code IDLE}. */
    void onError(S2TException error);

    /** The session moved to a new state. Optional. */
    default void onStateChange(SpeechToText.State state) {
    }
}
