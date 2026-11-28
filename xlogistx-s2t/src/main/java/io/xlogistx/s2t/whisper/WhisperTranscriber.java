package io.xlogistx.s2t.whisper;

import io.xlogistx.s2t.S2TConfig;
import io.xlogistx.s2t.S2TException;
import io.xlogistx.s2t.Transcriber;
import io.xlogistx.s2t.audio.AudioSource;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

import static java.lang.foreign.ValueLayout.JAVA_FLOAT;

/**
 * {@link Transcriber} backed by whisper.cpp through {@link WhisperNative}.
 * <p>
 * Holds one loaded model for its whole life. The native context must never be used by
 * two threads at once, and must not be freed while a transcription is running, so
 * {@code transcribe} and {@code close} take the same lock: calls run one after another
 * and {@code close} waits for a running one.
 * <p>
 * Runs on the CPU only.
 */
public final class WhisperTranscriber implements Transcriber {

    /**
     * Audio shorter than this is padded with silence. whisper.cpp returns nothing for
     * very short input (under 100 ms in release 1.9.1) and recognizes a lone word
     * poorly without some surrounding silence, so every utterance gets at least one
     * second.
     */
    static final int MIN_SAMPLES = AudioSource.SAMPLE_RATE;

    private final WhisperNative nativeApi;
    private final S2TConfig config;
    private final ReentrantLock lock = new ReentrantLock();

    /** Guarded by {@link #lock}; {@code null} once closed. */
    private MemorySegment context;

    private WhisperTranscriber(WhisperNative nativeApi, S2TConfig config, MemorySegment context) {
        this.nativeApi = nativeApi;
        this.config = config;
        this.context = context;
    }

    /**
     * Loads the native library (first use only) and the model named by the config.
     *
     * @throws S2TException when the platform is unsupported, the library cannot be
     *                      loaded, or the model file is missing or not a ggml model
     */
    public static WhisperTranscriber open(S2TConfig config) throws S2TException {
        Objects.requireNonNull(config, "config");
        Path model = config.modelPath().toAbsolutePath();
        if (!Files.isRegularFile(model) || !Files.isReadable(model)) {
            throw new S2TException("Model file not found or not readable: " + model);
        }

        WhisperNative nativeApi = WhisperNative.get(config.nativeCacheDir());
        nativeApi.setLogEnabled(config.nativeLogging());

        MemorySegment context;
        try (Arena arena = Arena.ofConfined()) {
            context = nativeApi.open(arena.allocateFrom(model.toString()), false);
        }
        if (context == null || context.equals(MemorySegment.NULL)) {
            throw new S2TException("The speech engine could not load the model " + model
                    + ". It must be a whisper.cpp ggml model such as ggml-base.en.bin;"
                    + " on Windows the path must not contain non-ASCII characters.");
        }
        return new WhisperTranscriber(nativeApi, config, context);
    }

    @Override
    public String transcribe(float[] samples, int offset, int length) throws S2TException {
        Objects.requireNonNull(samples, "samples");
        Objects.checkFromIndexSize(offset, length, samples.length);
        if (length == 0) {
            return "";
        }

        lock.lock();
        try {
            if (context == null) {
                throw new IllegalStateException("WhisperTranscriber is closed");
            }

            int count = Math.max(length, MIN_SAMPLES);
            try (Arena arena = Arena.ofConfined()) {
                // Arena memory starts zeroed, so anything past 'length' is silence.
                MemorySegment buffer = arena.allocate(JAVA_FLOAT, count);
                MemorySegment.copy(samples, offset, buffer, JAVA_FLOAT, 0, length);

                MemorySegment language = arena.allocateFrom(config.language());
                MemorySegment prompt = config.initialPrompt() == null
                        ? MemorySegment.NULL
                        : arena.allocateFrom(config.initialPrompt());

                int rc = nativeApi.transcribe(context, buffer, count, config.threads(),
                                              language, prompt, WhisperNative.FLAG_NO_CONTEXT);
                if (rc != 0) {
                    throw new S2TException("The speech engine failed with code " + rc
                            + " on " + length + " samples");
                }

                StringBuilder text = new StringBuilder();
                int segments = nativeApi.segmentCount(context);
                for (int i = 0; i < segments; i++) {
                    String segment = nativeApi.segmentText(context, i);
                    if (segment != null) {
                        text.append(segment);
                    }
                }
                return text.toString().trim();
            }
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void close() {
        lock.lock();
        try {
            MemorySegment c = context;
            context = null;
            if (c != null) {
                try {
                    nativeApi.close(c);
                } catch (S2TException ignored) {
                    // Nothing useful to do: the context is unusable either way.
                }
            }
        } finally {
            lock.unlock();
        }
    }

    /** The whisper.cpp release the native library was built from, for example {@code 1.9.1}. */
    public String engineVersion() throws S2TException {
        return nativeApi.whisperVersion();
    }

    /** The CPU features the native library uses, as reported by whisper.cpp. */
    public String systemInfo() throws S2TException {
        return nativeApi.systemInfo();
    }

    /** The native library file in use. */
    public Path libraryPath() {
        return nativeApi.libraryPath();
    }
}
