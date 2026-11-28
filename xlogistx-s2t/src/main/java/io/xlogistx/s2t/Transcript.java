package io.xlogistx.s2t;

/**
 * The result of one utterance.
 *
 * @param text            what was said, trimmed; empty when nothing was captured or
 *                        recognized. This is the engine's raw output: sentence
 *                        capitalization and punctuation are the engine's, and silence
 *                        can come back as a marker such as {@code [BLANK_AUDIO]}.
 * @param audioMillis     length of the captured audio
 * @param inferenceMillis time the speech engine took
 */
public record Transcript(String text, long audioMillis, long inferenceMillis) {

    public Transcript {
        text = text == null ? "" : text;
    }

    /** True when the engine produced no text at all. */
    public boolean isEmpty() {
        return text.isEmpty();
    }
}
