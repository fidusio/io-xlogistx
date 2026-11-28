package io.xlogistx.s2t;

import io.xlogistx.s2t.audio.AudioSource;
import io.xlogistx.s2t.audio.MicAudioSource;
import io.xlogistx.s2t.whisper.WhisperTranscriber;
import org.zoxweb.server.task.TaskUtil;

import java.util.concurrent.Executor;
import java.util.function.Supplier;

/**
 * Entry point of the module. Selects the platform, loads the native library and wires
 * the parts, so an application never names a platform or a native class.
 *
 * <pre>
 *   S2TConfig config = S2TConfig.builder().modelPath(model).build();
 *
 *   // microphone session
 *   SpeechToText stt = SpeechToTextFactory.create(config, listener);
 *   stt.start();          // key pressed
 *   stt.stop();           // key pressed again; listener.onTranscript(...) follows
 *   stt.close();          // application exit
 *
 *   // engine only
 *   try (Transcriber t = SpeechToTextFactory.createTranscriber(config)) {
 *       String text = t.transcribe(samples);
 *   }
 * </pre>
 *
 * The JVM must run with {@code --enable-native-access=ALL-UNNAMED} (or the executable
 * JAR's manifest must carry {@code Enable-Native-Access: ALL-UNNAMED}), as for every
 * FFM user.
 */
public final class SpeechToTextFactory {

    private SpeechToTextFactory() {
    }

    /**
     * The speech engine alone, with the model loaded. Close it when done.
     *
     * @throws S2TException on an unsupported platform, an unloadable native library,
     *                      or a missing or invalid model file
     */
    public static Transcriber createTranscriber(S2TConfig config) throws S2TException {
        return WhisperTranscriber.open(config);
    }

    /**
     * A microphone session whose transcriptions and callbacks run on zoxweb's default
     * task processor.
     */
    public static SpeechToText create(S2TConfig config, TranscriptListener listener) throws S2TException {
        return create(config, listener, TaskUtil.defaultTaskProcessor());
    }

    /**
     * A microphone session.
     *
     * @param executor runs each transcription and the listener callbacks that follow
     *                 it. Any executor works: the engine serializes calls itself. A
     *                 transcription keeps one of its threads busy for a second or more.
     */
    public static SpeechToText create(S2TConfig config, TranscriptListener listener, Executor executor)
            throws S2TException {
        return create(createTranscriber(config), MicAudioSource::new, listener, executor,
                      config.maxUtteranceSeconds());
    }

    /**
     * A session over any engine and any audio source. This is the seam tests use, and
     * what an application uses to listen to something other than the default microphone.
     * The session owns the transcriber and closes it in {@link SpeechToText#close()}.
     *
     * @param sources supplies a fresh {@link AudioSource} for each utterance
     */
    public static SpeechToText create(Transcriber transcriber,
                                      Supplier<? extends AudioSource> sources,
                                      TranscriptListener listener,
                                      Executor executor,
                                      int maxUtteranceSeconds) {
        return new DefaultSpeechToText(transcriber, sources, listener, executor, maxUtteranceSeconds);
    }
}
