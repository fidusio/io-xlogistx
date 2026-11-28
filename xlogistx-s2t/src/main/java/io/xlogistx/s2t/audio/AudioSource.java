package io.xlogistx.s2t.audio;

import io.xlogistx.s2t.S2TException;

/**
 * Supplies audio in the one format the speech engine takes: {@value #SAMPLE_RATE} Hz,
 * mono, 32-bit float in the range -1.0 to 1.0.
 * <p>
 * Implementations: {@link MicAudioSource} (the microphone) and {@link WavAudioSource}
 * (a file, for tests and batch use). An instance is used for one utterance:
 * {@code open()}, any number of {@code read()} calls, {@code close()}.
 */
public interface AudioSource extends AutoCloseable {

    /** Samples per second the engine expects. */
    int SAMPLE_RATE = 16_000;

    /**
     * @throws S2TException when the source cannot be opened
     */
    void open() throws S2TException;

    /**
     * Reads up to {@code length} samples into {@code buffer} starting at {@code offset}.
     * Blocks until some audio is available, but never for long: a live source returns
     * within about a tenth of a second so the caller can notice a stop request.
     *
     * @return the number of samples read; 0 when none arrived in time; -1 at the end of
     * the audio or after {@link #close()}
     */
    int read(float[] buffer, int offset, int length) throws S2TException;

    /** Releases the device or file. Idempotent, and safe to call from another thread. */
    @Override
    void close();
}
