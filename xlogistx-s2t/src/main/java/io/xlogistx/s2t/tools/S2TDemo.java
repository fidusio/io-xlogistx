package io.xlogistx.s2t.tools;

import io.xlogistx.s2t.S2TConfig;
import io.xlogistx.s2t.S2TException;
import io.xlogistx.s2t.SpeechToText;
import io.xlogistx.s2t.SpeechToTextFactory;
import io.xlogistx.s2t.Transcript;
import io.xlogistx.s2t.TranscriptListener;
import io.xlogistx.s2t.audio.AudioSource;
import io.xlogistx.s2t.audio.WavAudioSource;
import io.xlogistx.s2t.whisper.WhisperTranscriber;
import org.zoxweb.shared.util.ParamUtil;

import java.io.BufferedReader;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Command line over the module: the quickest way to see speech-to-text working, with
 * no application around it.
 *
 * <pre>
 *   S2TDemo model=&lt;ggml model file&gt; wav=&lt;audio file&gt;     transcribe a file and exit
 *   S2TDemo model=&lt;ggml model file&gt;                      microphone: Enter starts,
 *                                                        Enter stops, q quits
 *
 *   optional:  prompt="nano sudo systemctl"   vocabulary hint
 *              threads=4                      engine threads
 *              lang=en                        language code (en, fr, ar, ...) or auto;
 *                                             anything but en needs a multilingual model
 *              max=60                         longest utterance, seconds
 *              log=true                       show the engine's own diagnostics
 * </pre>
 *
 * Run with {@code --enable-native-access=ALL-UNNAMED}.
 */
public final class S2TDemo {

    private static final int UTF8_CODE_PAGE = 65001;

    private S2TDemo() {
    }

    public static void main(String[] args) {
        // Transcripts can be in any script, so the output is UTF-8 whatever the platform
        // default is; a Windows console is told to read it as UTF-8.
        consoleToUTF8();
        PrintStream out = new PrintStream(new FileOutputStream(FileDescriptor.out), true,
                                          StandardCharsets.UTF_8);
        int exit;
        try {
            ParamUtil.ParamMap params = ParamUtil.parse("=", args);
            String model = params.stringValue("model", true);
            if (model == null || model.isBlank()) {
                usage(out);
                System.exit(2);
                return;
            }

            S2TConfig.Builder builder = S2TConfig.builder()
                    .modelPath(Path.of(model))
                    .initialPrompt(params.stringValue("prompt", true))
                    .nativeLogging("true".equalsIgnoreCase(params.stringValue("log", true)));
            String lang = params.stringValue("lang", true);
            if (lang != null) {
                builder.language(lang);
            }
            String threads = params.stringValue("threads", true);
            if (threads != null) {
                builder.threads(Integer.parseInt(threads));
            }
            String max = params.stringValue("max", true);
            if (max != null) {
                builder.maxUtteranceSeconds(Integer.parseInt(max));
            }
            S2TConfig config = builder.build();

            String wav = params.stringValue("wav", true);
            exit = wav != null ? transcribeFile(config, Path.of(wav), out) : microphone(config, out);
        } catch (S2TException e) {
            out.println("ERROR: " + e.getMessage());
            exit = 1;
        } catch (IllegalArgumentException e) {
            out.println("ERROR: " + e.getMessage());
            usage(out);
            exit = 2;
        } catch (IOException e) {
            out.println("ERROR: " + e);
            exit = 1;
        }
        System.exit(exit);
    }

    private static int transcribeFile(S2TConfig config, Path wav, PrintStream out) throws S2TException {
        long t0 = System.nanoTime();
        try (WhisperTranscriber transcriber = WhisperTranscriber.open(config)) {
            long loadMillis = millisSince(t0);
            out.println("engine   whisper.cpp " + transcriber.engineVersion());
            out.println("library  " + transcriber.libraryPath());
            out.println("cpu      " + transcriber.systemInfo().trim());
            out.println("model    " + config.modelPath().toAbsolutePath() + "  (loaded in " + loadMillis + " ms)");

            float[] samples = WavAudioSource.readAll(wav);
            out.printf("audio    %s  (%.1f s)%n", wav.toAbsolutePath(),
                       samples.length / (double) AudioSource.SAMPLE_RATE);

            long t1 = System.nanoTime();
            String text = transcriber.transcribe(samples);
            out.println("time     " + millisSince(t1) + " ms");
            out.println("text     " + text);
        }
        return 0;
    }

    private static int microphone(S2TConfig config, PrintStream out) throws S2TException, IOException {
        // A private single thread, daemon so the JVM can exit; an application would pass
        // its own executor or use the factory's default.
        ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "s2t-demo");
            t.setDaemon(true);
            return t;
        });

        TranscriptListener listener = new TranscriptListener() {
            @Override
            public void onTranscript(Transcript transcript) {
                out.printf("  [%.1f s audio, %d ms]  %s%n", transcript.audioMillis() / 1000.0,
                           transcript.inferenceMillis(),
                           transcript.isEmpty() ? "(nothing recognized)" : transcript.text());
                out.println("Enter = start listening, q = quit");
            }

            @Override
            public void onError(S2TException error) {
                out.println("  ERROR: " + error.getMessage());
                out.println("Enter = start listening, q = quit");
            }

            @Override
            public void onStateChange(SpeechToText.State state) {
                switch (state) {
                    case LISTENING -> out.println("  listening... Enter = stop, c = cancel");
                    case TRANSCRIBING -> out.println("  transcribing...");
                    default -> {
                    }
                }
            }
        };

        out.println("Loading model " + config.modelPath().toAbsolutePath() + " ...");
        try (SpeechToText stt = SpeechToTextFactory.create(config, listener, executor)) {
            out.println("Enter = start listening, q = quit");
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
            String line;
            while ((line = in.readLine()) != null) {
                String command = line.trim().toLowerCase();
                if (command.equals("q") || command.equals("quit") || command.equals("exit")) {
                    break;
                }
                switch (stt.state()) {
                    case IDLE -> stt.start();
                    case LISTENING -> {
                        if (command.equals("c")) {
                            stt.cancel();
                            out.println("  cancelled. Enter = start listening, q = quit");
                        } else {
                            stt.stop();
                        }
                    }
                    case TRANSCRIBING -> out.println("  still transcribing, wait for the result");
                    default -> {
                    }
                }
            }
        } finally {
            executor.shutdown();
        }
        return 0;
    }

    /**
     * Windows only: switches the console's output code page to UTF-8 (65001) and puts
     * the previous one back when the JVM exits, because the code page outlives the
     * process in the same console window. Does nothing elsewhere, when there is no
     * console, or when the call fails: the demo then still writes UTF-8 bytes.
     */
    private static void consoleToUTF8() {
        if (!System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows")) {
            return;
        }
        try {
            Linker linker = Linker.nativeLinker();
            SymbolLookup kernel32 = SymbolLookup.libraryLookup("kernel32", Arena.global());
            MethodHandle getCP = linker.downcallHandle(
                    kernel32.find("GetConsoleOutputCP").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT));
            MethodHandle setCP = linker.downcallHandle(
                    kernel32.find("SetConsoleOutputCP").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));

            int previous = (int) getCP.invokeExact();
            // 0 means the process has no console.
            if (previous == 0 || previous == UTF8_CODE_PAGE) {
                return;
            }
            if ((int) setCP.invokeExact(UTF8_CODE_PAGE) != 0) {
                Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                    try {
                        int ignored = (int) setCP.invokeExact(previous);
                    } catch (Throwable ignored) {
                        // The console keeps UTF-8; nothing else to do at exit.
                    }
                }, "s2t-demo-console"));
            }
        } catch (Throwable ignored) {
            // No console API: the output is UTF-8 bytes either way.
        }
    }

    private static long millisSince(long nanos) {
        return (System.nanoTime() - nanos) / 1_000_000;
    }

    private static void usage(PrintStream out) {
        out.println("Usage:");
        out.println("  S2TDemo model=<ggml model file> wav=<audio file>   transcribe a file");
        out.println("  S2TDemo model=<ggml model file>                    use the microphone");
        out.println("Optional: prompt=\"words\" threads=<n> lang=<code|auto> max=<seconds> log=true");
    }
}
