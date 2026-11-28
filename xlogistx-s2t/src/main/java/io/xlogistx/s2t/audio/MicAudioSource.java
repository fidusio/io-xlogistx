package io.xlogistx.s2t.audio;

import io.xlogistx.s2t.S2TException;

import javax.sound.sampled.AudioFormat;
import javax.sound.sampled.AudioSystem;
import javax.sound.sampled.DataLine;
import javax.sound.sampled.LineUnavailableException;
import javax.sound.sampled.TargetDataLine;

/**
 * The system's default microphone, through Java Sound. Works the same on every
 * platform Java Sound supports, so it is not platform code.
 * <p>
 * The line is asked for 16 kHz, 16-bit, mono, which is what the engine wants. A device
 * that refuses 16 kHz is opened at 48 kHz or 44.1 kHz instead and converted on the
 * fly with {@link PcmConverter#resample}.
 * <p>
 * Audio is read in chunks of {@value #CHUNK_MILLIS} ms, so {@link #read} returns at
 * that pace and the caller can react to a stop request promptly.
 */
public final class MicAudioSource implements AudioSource {

    /** Capture rates to try, in order of preference. */
    private static final float[] RATES = {SAMPLE_RATE, 48_000f, 44_100f};

    private static final int CHUNK_MILLIS = 100;

    private volatile TargetDataLine line;
    private volatile boolean closed;
    private float lineRate;
    private byte[] raw;
    private float[] scratch;

    @Override
    public synchronized void open() throws S2TException {
        if (line != null) {
            throw new IllegalStateException("MicAudioSource is already open");
        }

        Exception last = null;
        for (float rate : RATES) {
            AudioFormat format = new AudioFormat(rate, 16, 1, true, false);
            DataLine.Info info = new DataLine.Info(TargetDataLine.class, format);
            try {
                if (!AudioSystem.isLineSupported(info)) {
                    continue;
                }
                TargetDataLine candidate = (TargetDataLine) AudioSystem.getLine(info);
                candidate.open(format);
                candidate.start();

                int frames = Math.round(rate * CHUNK_MILLIS / 1000f);
                raw = new byte[frames * 2];
                scratch = new float[frames];
                lineRate = rate;
                closed = false;
                line = candidate;
                return;
            } catch (LineUnavailableException | SecurityException | IllegalArgumentException e) {
                last = e;
            }
        }

        String detail = last == null ? "no capture device offers 16-bit mono audio" : last.toString();
        throw new S2TException("No usable microphone: " + detail
                + ". Check that a microphone is connected and that this application is"
                + " allowed to use it (Windows: Settings > Privacy > Microphone >"
                + " \"Let desktop apps access your microphone\").", last);
    }

    @Override
    public int read(float[] buffer, int offset, int length) throws S2TException {
        TargetDataLine l = line;
        if (l == null || closed) {
            return -1;
        }

        int wanted = Math.min(length, SAMPLE_RATE * CHUNK_MILLIS / 1000);
        if (wanted <= 0) {
            return 0;
        }
        boolean direct = lineRate == SAMPLE_RATE;
        int frames = direct
                ? wanted
                : Math.min(scratch.length, (int) Math.floor(wanted * (double) lineRate / SAMPLE_RATE));

        int bytes;
        try {
            bytes = l.read(raw, 0, frames * 2);
        } catch (RuntimeException e) {
            if (closed) {
                return -1;
            }
            throw new S2TException("Reading from the microphone failed: " + e, e);
        }
        if (bytes <= 0) {
            return closed || !l.isOpen() ? -1 : 0;
        }

        int got = PcmConverter.pcm16leToFloat(raw, 0, bytes, scratch, 0);
        if (direct) {
            System.arraycopy(scratch, 0, buffer, offset, got);
            return got;
        }
        float[] converted = PcmConverter.resample(scratch, got, lineRate, SAMPLE_RATE);
        int n = Math.min(converted.length, length);
        System.arraycopy(converted, 0, buffer, offset, n);
        return n;
    }

    /**
     * Stops and releases the line. A {@code read} blocked in another thread returns.
     * Not synchronized with {@code read} on purpose: it must be able to interrupt one.
     */
    @Override
    public void close() {
        closed = true;
        TargetDataLine l = line;
        line = null;
        if (l != null) {
            try {
                l.stop();
            } finally {
                l.close();
            }
        }
    }

    /** The rate the device was actually opened at; 0 before {@link #open()}. */
    public float deviceSampleRate() {
        return lineRate;
    }
}
