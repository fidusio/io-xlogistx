package io.xlogistx.s2t;

/**
 * The speech engine on its own: audio samples in, text out, no microphone.
 * <p>
 * Samples are {@value io.xlogistx.s2t.audio.AudioSource#SAMPLE_RATE} Hz, mono,
 * in the range -1.0 to 1.0. An implementation serializes calls internally, so it is
 * safe to share between threads; calls simply run one after another.
 */
public interface Transcriber extends AutoCloseable {

    /**
     * Transcribes {@code length} samples starting at {@code offset}. Blocks until the
     * engine has finished.
     *
     * @return the recognized text, trimmed; empty when nothing was recognized
     * @throws S2TException          when the engine reports an error
     * @throws IllegalStateException when this transcriber has been closed
     */
    String transcribe(float[] samples, int offset, int length) throws S2TException;

    /** Transcribes the whole array. */
    default String transcribe(float[] samples) throws S2TException {
        return transcribe(samples, 0, samples.length);
    }

    /** Releases the engine. Waits for a running transcription to finish. Idempotent. */
    @Override
    void close();
}
