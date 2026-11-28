package io.xlogistx.s2t.whisper;

import io.xlogistx.s2t.S2TConfig;
import io.xlogistx.s2t.S2TException;
import io.xlogistx.s2t.SpeechToText;
import io.xlogistx.s2t.SpeechToTextFactory;
import io.xlogistx.s2t.Transcript;
import io.xlogistx.s2t.TranscriptListener;
import io.xlogistx.s2t.audio.AudioSource;
import io.xlogistx.s2t.audio.WavAudioSource;
import io.xlogistx.s2t.platform.NativePlatforms;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The real thing: the packaged native library, a real model, a real recording.
 * <p>
 * Needs a ggml model file, which is far too large to keep in the repository. The test
 * is SKIPPED unless one is found, in this order:
 * <ol>
 *   <li>system property {@code s2t.model} ({@code mvn test -Ds2t.model=D:/path/ggml-base.en.bin})</li>
 *   <li>environment variable {@code S2T_MODEL}</li>
 *   <li>{@code ~/.xlogistx/s2t/models/ggml-base.en.bin}</li>
 * </ol>
 * It is also skipped on a platform the module has no native library for.
 * <p>
 * The recording is {@code jfk.wav}, the 11-second sample that ships with whisper.cpp.
 */
class WhisperTranscriberLiveTest {

    private static final String EXPECTED = "ask not what your country can do for you";

    private static Path model;
    private static Path jfk;

    @BeforeAll
    static void locate() throws Exception {
        try {
            NativePlatforms.current();
        } catch (S2TException e) {
            assumeTrue(false, e.getMessage());
        }

        String configured = System.getProperty("s2t.model");
        if (configured == null || configured.isBlank()) {
            configured = System.getenv("S2T_MODEL");
        }
        model = configured != null && !configured.isBlank()
                ? Path.of(configured)
                : Path.of(System.getProperty("user.home"), ".xlogistx", "s2t", "models", "ggml-base.en.bin");
        assumeTrue(Files.isRegularFile(model), "no model file at " + model + "; set -Ds2t.model=<path>");

        URL resource = WhisperTranscriberLiveTest.class.getResource("/jfk.wav");
        assertNotNull(resource, "jfk.wav is missing from src/test/resources");
        jfk = Path.of(resource.toURI());
    }

    private static S2TConfig config() {
        return S2TConfig.builder().modelPath(model).build();
    }

    @Test
    void transcribesTheSampleRecording() throws Exception {
        float[] samples = WavAudioSource.readAll(jfk);
        assertEquals(176_000, samples.length, 100, "jfk.wav should be about 11 s at 16 kHz");

        try (WhisperTranscriber transcriber = WhisperTranscriber.open(config())) {
            assertEquals("1.9.1", transcriber.engineVersion());
            assertTrue(transcriber.systemInfo().contains("AVX2 = 1"), transcriber.systemInfo());
            assertTrue(Files.isRegularFile(transcriber.libraryPath()));

            String text = transcriber.transcribe(samples);
            assertTrue(text.toLowerCase(Locale.ROOT).contains(EXPECTED), text);
        }
    }

    /** The same context must give the same answer again: nothing leaks between calls. */
    @Test
    void theSameTranscriberCanBeUsedRepeatedly() throws Exception {
        float[] samples = WavAudioSource.readAll(jfk);
        try (WhisperTranscriber transcriber = WhisperTranscriber.open(config())) {
            String first = transcriber.transcribe(samples);
            String second = transcriber.transcribe(samples);
            String third = transcriber.transcribe(samples);
            assertEquals(first, second);
            assertEquals(first, third);
        }
    }

    @Test
    void aVocabularyHintAndAnOffsetWindowAreAccepted() throws Exception {
        float[] samples = WavAudioSource.readAll(jfk);
        S2TConfig hinted = S2TConfig.builder().modelPath(model)
                                    .initialPrompt("Americans country fellow").threads(2).build();
        try (WhisperTranscriber transcriber = WhisperTranscriber.open(hinted)) {
            // Skip the first second: still the same famous sentence.
            String text = transcriber.transcribe(samples, AudioSource.SAMPLE_RATE,
                                                 samples.length - AudioSource.SAMPLE_RATE);
            assertTrue(text.toLowerCase(Locale.ROOT).contains("country"), text);
        }
    }

    /** Short and silent input must come back as text (possibly a blank marker), not crash. */
    @Test
    void veryShortAndSilentAudioDoNotFail() throws Exception {
        try (WhisperTranscriber transcriber = WhisperTranscriber.open(config())) {
            assertNotNull(transcriber.transcribe(new float[800]));      // 50 ms, padded to 1 s
            assertNotNull(transcriber.transcribe(new float[32_000]));   // 2 s of silence
            assertEquals("", transcriber.transcribe(new float[0]));
        }
    }

    @Test
    void usingAClosedTranscriberIsAnError() throws Exception {
        WhisperTranscriber transcriber = WhisperTranscriber.open(config());
        transcriber.close();
        transcriber.close();                                            // idempotent
        assertThrows(IllegalStateException.class, () -> transcriber.transcribe(new float[16_000]));
    }

    @Test
    void aMissingModelIsReportedWithItsPath() {
        Path missing = Path.of("no-such-directory", "ggml-nope.bin");
        S2TException e = assertThrows(S2TException.class,
                                      () -> WhisperTranscriber.open(S2TConfig.builder().modelPath(missing).build()));
        assertTrue(e.getMessage().contains("ggml-nope.bin"), e.getMessage());
    }

    @Test
    void aFileThatIsNotAModelIsRejected(@TempDir Path dir) throws Exception {
        Path fake = Files.writeString(dir.resolve("not-a-model.bin"), "this is not a ggml model");
        S2TException e = assertThrows(S2TException.class,
                                      () -> WhisperTranscriber.open(S2TConfig.builder().modelPath(fake).build()));
        assertTrue(e.getMessage().contains("could not load the model"), e.getMessage());
    }

    /** End to end through the session, with the WAV file standing in for the microphone. */
    @Test
    void aSessionOverTheRecordingDeliversTheTranscript() throws Exception {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        CountDownLatch done = new CountDownLatch(1);
        AtomicReference<Transcript> transcript = new AtomicReference<>();
        AtomicReference<S2TException> error = new AtomicReference<>();
        TranscriptListener listener = new TranscriptListener() {
            @Override
            public void onTranscript(Transcript t) {
                transcript.set(t);
                done.countDown();
            }

            @Override
            public void onError(S2TException e) {
                error.set(e);
                done.countDown();
            }
        };

        try (SpeechToText stt = SpeechToTextFactory.create(SpeechToTextFactory.createTranscriber(config()),
                                                          () -> new WavAudioSource(jfk),
                                                          listener, executor, 60)) {
            stt.start();        // the file ends by itself, which ends the utterance
            assertTrue(done.await(120, TimeUnit.SECONDS), "no result within two minutes");
        } finally {
            executor.shutdownNow();
        }

        assertEquals(null, error.get());
        assertTrue(transcript.get().text().toLowerCase(Locale.ROOT).contains(EXPECTED), transcript.get().text());
        assertEquals(11_000, transcript.get().audioMillis(), 100);
    }
}
