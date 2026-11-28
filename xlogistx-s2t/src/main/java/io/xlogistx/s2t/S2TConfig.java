package io.xlogistx.s2t;

import java.nio.file.Path;
import java.util.Locale;
import java.util.Objects;

/**
 * Immutable settings for a {@link Transcriber} or a {@link SpeechToText} session.
 *
 * <pre>
 *   S2TConfig config = S2TConfig.builder()
 *           .modelPath(Path.of("D:/models/ggml-base.en.bin"))
 *           .initialPrompt("nano sudo systemctl grep chmod")
 *           .build();
 * </pre>
 *
 * Only {@code modelPath} is required.
 */
public final class S2TConfig {

    public static final String DEFAULT_LANGUAGE = "en";
    /**
     * Language value that makes the engine detect the spoken language by itself, once
     * per transcription. Needs a multilingual model ({@code ggml-base.bin}, not
     * {@code ggml-base.en.bin}).
     */
    public static final String LANGUAGE_AUTO = "auto";
    public static final int DEFAULT_MAX_UTTERANCE_SECONDS = 60;
    public static final int DEFAULT_MAX_THREADS = 4;

    private final Path modelPath;
    private final String language;
    private final int threads;
    private final String initialPrompt;
    private final int maxUtteranceSeconds;
    private final Path nativeCacheDir;
    private final boolean nativeLogging;

    private S2TConfig(Builder b) {
        this.modelPath = b.modelPath;
        this.language = b.language;
        this.threads = b.threads;
        this.initialPrompt = b.initialPrompt;
        this.maxUtteranceSeconds = b.maxUtteranceSeconds;
        this.nativeCacheDir = b.nativeCacheDir;
        this.nativeLogging = b.nativeLogging;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** {@code ~/.xlogistx/s2t/native}: where the packaged native libraries are unpacked. */
    public static Path defaultNativeCacheDir() {
        return Path.of(System.getProperty("user.home", "."), ".xlogistx", "s2t", "native");
    }

    /** {@code min(4, available processors)}. */
    public static int defaultThreads() {
        return Math.max(1, Math.min(DEFAULT_MAX_THREADS, Runtime.getRuntime().availableProcessors()));
    }

    /** The ggml model file on disk, for example {@code ggml-base.en.bin}. */
    public Path modelPath() {
        return modelPath;
    }

    /**
     * Language handed to the engine: a lower-case code such as {@code en}, {@code fr} or
     * {@code ar}, or {@value #LANGUAGE_AUTO}. Default {@value #DEFAULT_LANGUAGE}.
     */
    public String language() {
        return language;
    }

    /** Threads the engine uses for one transcription. */
    public int threads() {
        return threads;
    }

    /** Vocabulary hint, or {@code null} for none. */
    public String initialPrompt() {
        return initialPrompt;
    }

    /** A listening session stops capturing by itself at this length. */
    public int maxUtteranceSeconds() {
        return maxUtteranceSeconds;
    }

    /** Where the native libraries packaged in the JAR are unpacked before loading. */
    public Path nativeCacheDir() {
        return nativeCacheDir;
    }

    /** When true the engine writes its own diagnostics to stderr. Default false. */
    public boolean nativeLogging() {
        return nativeLogging;
    }

    @Override
    public String toString() {
        return "S2TConfig{modelPath=" + modelPath
                + ", language=" + language
                + ", threads=" + threads
                + ", initialPrompt=" + (initialPrompt == null ? "none" : "'" + initialPrompt + "'")
                + ", maxUtteranceSeconds=" + maxUtteranceSeconds
                + ", nativeCacheDir=" + nativeCacheDir
                + ", nativeLogging=" + nativeLogging + '}';
    }

    public static final class Builder {

        private Path modelPath;
        private String language = DEFAULT_LANGUAGE;
        private int threads = defaultThreads();
        private String initialPrompt;
        private int maxUtteranceSeconds = DEFAULT_MAX_UTTERANCE_SECONDS;
        private Path nativeCacheDir = defaultNativeCacheDir();
        private boolean nativeLogging;

        private Builder() {
        }

        public Builder modelPath(Path modelPath) {
            this.modelPath = modelPath;
            return this;
        }

        /**
         * The spoken language: a code such as {@code en}, {@code fr} or {@code ar} to
         * force one, or {@link #LANGUAGE_AUTO} to let the engine detect it for every
         * transcription. Anything but {@code en} needs a multilingual model. Case and
         * surrounding blanks are ignored; {@code null} or blank means
         * {@value #DEFAULT_LANGUAGE}.
         */
        public Builder language(String language) {
            this.language = language;
            return this;
        }

        /** Shorthand for {@code language(LANGUAGE_AUTO)}. */
        public Builder autoDetectLanguage() {
            return language(LANGUAGE_AUTO);
        }

        public Builder threads(int threads) {
            this.threads = threads;
            return this;
        }

        /** A few words the speaker is likely to say; biases recognition toward them. */
        public Builder initialPrompt(String initialPrompt) {
            this.initialPrompt = initialPrompt == null || initialPrompt.isBlank() ? null : initialPrompt;
            return this;
        }

        public Builder maxUtteranceSeconds(int maxUtteranceSeconds) {
            this.maxUtteranceSeconds = maxUtteranceSeconds;
            return this;
        }

        public Builder nativeCacheDir(Path nativeCacheDir) {
            this.nativeCacheDir = nativeCacheDir;
            return this;
        }

        public Builder nativeLogging(boolean nativeLogging) {
            this.nativeLogging = nativeLogging;
            return this;
        }

        /**
         * @throws NullPointerException     when {@code modelPath} was not set
         * @throws IllegalArgumentException on a non-positive thread count or length
         */
        public S2TConfig build() {
            Objects.requireNonNull(modelPath, "modelPath");
            Objects.requireNonNull(nativeCacheDir, "nativeCacheDir");
            // The engine matches language codes exactly, in lower case.
            language = language == null || language.isBlank()
                    ? DEFAULT_LANGUAGE
                    : language.trim().toLowerCase(Locale.ROOT);
            if (threads < 1) {
                throw new IllegalArgumentException("threads must be >= 1, got " + threads);
            }
            if (maxUtteranceSeconds < 1) {
                throw new IllegalArgumentException(
                        "maxUtteranceSeconds must be >= 1, got " + maxUtteranceSeconds);
            }
            return new S2TConfig(this);
        }
    }
}
