package io.xlogistx.s2t;

/**
 * Thrown when speech-to-text cannot be set up or a transcription fails: unsupported
 * platform, native library not loadable, model file missing or not a model, no usable
 * microphone, or an error reported by the speech engine.
 * <p>
 * Checked deliberately: every one of these is a condition the caller must handle and
 * can report to the user. Misuse of the API (calling {@code start()} twice, using a
 * closed object) is an {@link IllegalStateException} instead.
 */
public final class S2TException extends Exception {

    private static final long serialVersionUID = 1L;

    public S2TException(String msg) {
        super(msg);
    }

    public S2TException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
