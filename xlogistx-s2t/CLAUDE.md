# Claude Code Instructions for the xlogistx-s2t module

## Purpose

Offline speech-to-text as a plain Java library: microphone audio in, text out, no
network call. The engine is [whisper.cpp](https://github.com/ggml-org/whisper.cpp),
called through the JDK 25 FFM API (`java.lang.foreign`), no JNI and no third-party
Java dependency. Built to be embedded in any XlogistX application; JSSH is the first
planned consumer (that integration is version 1.1 and is NOT in this module).

Status (2026-11-24): version 1, Windows x86-64 only. macOS and Linux are recognized
and rejected with a clear message until their native libraries are built.

## Layout

```
xlogistx-s2t/
├── pom.xml                  Java 25; depends on zoxweb-core only (ParamUtil, TaskUtil)
├── native/                  SOURCE of the native library (not compiled by Maven)
│   ├── xs2t_shim.c            the C functions Java binds
│   ├── CMakeLists.txt         builds the standalone libwhisper.dll
│   └── README.md              how to rebuild it
└── src/main/
    ├── resources/native/windows-x86_64/
    │   ├── libwinpthread-1.dll   MinGW thread runtime, loaded first
    │   └── libwhisper.dll        whisper.cpp + ggml + libstdc++ + libgcc, exports xs2t_*
    └── java/io/xlogistx/s2t/
        ├── SpeechToText            session interface: start / stop / cancel / close
        ├── Transcriber             engine interface: float[] samples -> String
        ├── TranscriptListener      onTranscript / onError / onStateChange
        ├── Transcript              record: text, audioMillis, inferenceMillis
        ├── S2TConfig               immutable settings + builder (only modelPath required)
        ├── S2TException            checked: setup and engine failures
        ├── SpeechToTextFactory     THE entry point; wires everything
        ├── DefaultSpeechToText     the session implementation (package-private)
        ├── audio/
        │   ├── AudioSource           16 kHz mono float supplier
        │   ├── MicAudioSource        default microphone via javax.sound.sampled
        │   ├── WavAudioSource        a file as a source (tests, batch)
        │   └── PcmConverter          16-bit -> float, stereo -> mono, resampling
        ├── whisper/
        │   ├── WhisperNative         FFM downcall handles for the nine xs2t_* functions
        │   └── WhisperTranscriber    Transcriber over one loaded model
        ├── platform/
        │   ├── NativePlatform        interface: resource dir + files to load, in order
        │   ├── NativePlatforms       os.name / os.arch -> NativePlatform
        │   ├── NativeLibraryLoader   unpack from the JAR, load dependencies
        │   └── windows/WindowsX64Platform
        └── tools/S2TDemo           command line: transcribe a WAV, or use the microphone
```

## How the platform split works

Same idea as `xlogistx-net`, but much thinner, because the native API is identical on
every OS. ALL of the code is shared: bindings, transcriber, capture, session. A
platform contributes exactly two facts through `NativePlatform`: which classpath
directory holds its binaries, and which files to load in what order.

To add macOS or Linux:
1. Build the native library for it from `native/` (see `native/README.md`).
2. Put the files in `src/main/resources/native/<os>-<arch>/`.
3. Add a class beside `platform/windows/WindowsX64Platform` in its own package
   (`platform/linux`, `platform/darwin`).
4. Return it from `NativePlatforms.forOs` and extend `NativePlatformsTest`.

Nothing else changes. Do NOT add per-platform variants of `WhisperNative` or of the
audio classes.

## The native shim (IMPORTANT)

Java does not call whisper.cpp's API directly. whisper.cpp passes two large structs
by value (`whisper_context_params`, `whisper_full_params`) and both change between
releases; the Java binding bundled with whisper.cpp is already out of date for that
reason. Instead `native/xs2t_shim.c` is compiled INTO `libwhisper.dll` and exports nine
functions that take only pointers, ints and C strings:

| C function | Purpose |
|---|---|
| `xs2t_abi_version()` | shim function-set version; Java requires `WhisperNative.SUPPORTED_ABI` |
| `xs2t_whisper_version()` | whisper.cpp release, e.g. `1.9.1` |
| `xs2t_system_info()` | CPU features in use |
| `xs2t_set_log_enabled(int)` | 0 silences whisper's stderr logging |
| `xs2t_open(path, use_gpu)` | load a model, returns the context or NULL |
| `xs2t_close(ctx)` | free the context |
| `xs2t_transcribe(ctx, samples, n, threads, language, prompt, flags)` | run recognition, 0 = ok |
| `xs2t_segment_count(ctx)` | segments from the last transcribe |
| `xs2t_segment_text(ctx, i)` | UTF-8 text of one segment |

Rules:
- No whisper struct layout may ever appear in Java. Need another engine option?
  Add a parameter or a flag bit in the shim, bump `XS2T_ABI_VERSION` in the C file and
  `SUPPORTED_ABI` in `WhisperNative`, rebuild the DLL.
- `native/xs2t_shim.c`, `native/CMakeLists.txt` and the DLL in `src/main/resources`
  must always come from the same build. After any native change: rebuild, copy both
  DLLs into `src/main/resources/native/windows-x86_64/`, run the live test.
- Upgrading whisper.cpp = check out the new tag, rebuild, copy. No Java change, except
  the version string asserted in `WhisperTranscriberLiveTest`.

## Architectural rules

1. **`SpeechToTextFactory` is the only entry point** an application uses. It never
   names a platform or a class in `whisper/`.
2. **One native context is never used by two threads at once and never freed during a
   call.** `WhisperTranscriber` enforces both with one lock taken by `transcribe` and
   `close`. Do not add an unlocked path to the context.
3. **The library is loaded once per JVM** (`WhisperNative.get`, `NativeLibraryLoader`),
   into `Arena.global()`. It is never unloaded.
4. **Executors are passed in.** No `ForkJoinPool.commonPool()`, no `ThreadLocal`. The
   session creates exactly one thread of its own per utterance (`s2t-capture`, daemon).
5. **No listener callback while holding the session lock**, and a listener exception
   never propagates (`DefaultSpeechToText.notifyState` / `notifyError`).
6. **The model file is never packaged and never downloaded by this module.** The
   application passes `S2TConfig.modelPath`.
7. **No dependency on `xlogistx-gui-audio`.** That module carries the Swing and PDF
   stack; GUI applications depend on this module, not the reverse. `MicAudioSource`
   uses the same audio format as `io.xlogistx.audio.AudioUtil.defaultAudioFormat()`.

## Build / run

```bash
# Build (tests are skipped by default in this project)
mvn -pl xlogistx-s2t install

# Unit tests only: no model, no native library, any OS
mvn -pl xlogistx-s2t test -DskipTests=false

# Plus the live test: real DLL, real model, jfk.wav
mvn -pl xlogistx-s2t test -DskipTests=false -Ds2t.model=D:/dev/data/vscode/Whisper/models/ggml-base.en.bin

# Demo: transcribe a file
java --enable-native-access=ALL-UNNAMED -cp <classpath> io.xlogistx.s2t.tools.S2TDemo \
     model=D:/dev/data/vscode/Whisper/models/ggml-base.en.bin wav=some.wav

# Demo: microphone (Enter starts, Enter stops, c cancels, q quits)
java --enable-native-access=ALL-UNNAMED -cp <classpath> io.xlogistx.s2t.tools.S2TDemo \
     model=D:/dev/data/vscode/Whisper/models/ggml-base.en.bin prompt="nano sudo systemctl"
```

`--enable-native-access=ALL-UNNAMED` is required on JDK 25 (surefire already passes
it). An executable JAR can carry `Enable-Native-Access: ALL-UNNAMED` in its manifest
instead.

System properties:
- `xlogistx.s2t.native.dir` - load the DLLs from this directory instead of unpacking
  the packaged ones (for testing a fresh native build).
- `s2t.model` (tests only) - model file for `WhisperTranscriberLiveTest`.

## Tests

| Test | Needs | Covers |
|---|---|---|
| `platform/NativePlatformsTest` | nothing | os/arch selection, darwin-vs-win trap, DLLs are packaged |
| `audio/PcmConverterTest` | nothing | PCM conversion, mono mix, resampling lengths |
| `DefaultSpeechToTextTest` | nothing | the whole state machine with a fake source and engine |
| `whisper/WhisperTranscriberLiveTest` | Windows x64 + a model file | real transcription of `jfk.wav`, repeat use, short/silent audio, bad model, session end to end. SKIPPED when no model is found |

## Known limitations / gotchas

- **Windows x86-64 only**, and the CPU must have AVX2 (the DLL is a portable build:
  SSE4.2, AVX, AVX2, FMA, F16C, BMI2, no AVX-512). There is no runtime CPU check: on a
  CPU without AVX2 the process dies with an illegal-instruction fault.
- **Model path must be ASCII-compatible on Windows.** whisper.cpp opens the file with
  a narrow-character path under MinGW.
- **`Transcript.text` is the engine's raw output.** It capitalizes and punctuates like
  a sentence, and silence can come back as a marker such as `[BLANK_AUDIO]`. Cleaning
  that up for a shell command line is the consuming application's job.
- **CPU only.** `xs2t_open` is always called with `use_gpu = 0`; the DLL has no GPU
  backend compiled in.
- **`MicAudioSource` has not been exercised with a real microphone in an automated
  test** (there is no device on a build machine). Verify with `S2TDemo`.
- **Native libraries are unpacked to `~/.xlogistx/s2t/native/<platform>/<fingerprint>/`**
  and never deleted; each new DLL build leaves a new ~5 MB directory there.
- **Two files, not one, on Windows.** CLion's bundled MinGW builds winpthread against
  the UCRT while the rest of the toolchain uses msvcrt, so winpthread cannot be linked
  statically; `libwinpthread-1.dll` ships beside `libwhisper.dll`.
