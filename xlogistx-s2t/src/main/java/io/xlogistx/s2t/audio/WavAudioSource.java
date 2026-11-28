package io.xlogistx.s2t.audio;

import io.xlogistx.s2t.S2TException;

import javax.sound.sampled.AudioFormat;
import javax.sound.sampled.AudioInputStream;
import javax.sound.sampled.AudioSystem;
import javax.sound.sampled.UnsupportedAudioFileException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * An audio file as an {@link AudioSource}: for tests, for transcribing recordings, and
 * for trying the engine on a machine with no microphone.
 * <p>
 * Reads anything Java Sound can decode to PCM (WAV in practice), mixes it to mono and
 * converts it to {@value AudioSource#SAMPLE_RATE} Hz. The whole file is held in
 * memory: one minute is under 4 MB.
 */
public final class WavAudioSource implements AudioSource {

    private final Path file;
    private float[] samples;
    private int position;
    private volatile boolean closed;

    public WavAudioSource(Path file) {
        this.file = Objects.requireNonNull(file, "file");
    }

    /**
     * Decodes a whole file to {@value AudioSource#SAMPLE_RATE} Hz mono floats.
     *
     * @throws S2TException when the file is missing, unreadable or not decodable audio
     */
    public static float[] readAll(Path file) throws S2TException {
        if (!Files.isRegularFile(file)) {
            throw new S2TException("Audio file not found: " + file.toAbsolutePath());
        }
        try (AudioInputStream in = AudioSystem.getAudioInputStream(file.toFile())) {
            AudioFormat source = in.getFormat();
            int channels = source.getChannels();
            float rate = source.getSampleRate();
            AudioFormat pcm = new AudioFormat(AudioFormat.Encoding.PCM_SIGNED,
                                              rate, 16, channels, channels * 2, rate, false);

            byte[] bytes;
            if (source.matches(pcm)) {
                bytes = in.readAllBytes();
            } else {
                try (AudioInputStream decoded = AudioSystem.getAudioInputStream(pcm, in)) {
                    bytes = decoded.readAllBytes();
                }
            }

            float[] interleaved = new float[bytes.length / 2];
            PcmConverter.pcm16leToFloat(bytes, 0, bytes.length, interleaved, 0);
            float[] mono = PcmConverter.mixToMono(interleaved, channels);
            return rate == SAMPLE_RATE
                    ? mono
                    : PcmConverter.resample(mono, mono.length, rate, SAMPLE_RATE);
        } catch (UnsupportedAudioFileException | IllegalArgumentException e) {
            throw new S2TException("Not an audio file Java Sound can decode: "
                    + file.toAbsolutePath() + " (" + e.getMessage() + ")", e);
        } catch (IOException e) {
            throw new S2TException("Cannot read audio file " + file.toAbsolutePath()
                    + ": " + e.getMessage(), e);
        }
    }

    @Override
    public void open() throws S2TException {
        samples = readAll(file);
        position = 0;
        closed = false;
    }

    @Override
    public int read(float[] buffer, int offset, int length) {
        float[] s = samples;
        if (closed || s == null || position >= s.length) {
            return -1;
        }
        int n = Math.min(length, s.length - position);
        System.arraycopy(s, position, buffer, offset, n);
        position += n;
        return n;
    }

    @Override
    public void close() {
        closed = true;
    }
}
