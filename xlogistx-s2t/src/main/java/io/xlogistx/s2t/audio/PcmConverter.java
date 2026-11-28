package io.xlogistx.s2t.audio;

/**
 * Sample-format arithmetic: 16-bit PCM to float, stereo to mono, and sample-rate
 * conversion. Pure functions, no audio devices.
 */
public final class PcmConverter {

    private PcmConverter() {
    }

    /**
     * Converts signed 16-bit little-endian PCM to floats in the range -1.0 to 1.0.
     * A trailing odd byte is ignored.
     *
     * @return the number of samples written to {@code out}
     */
    public static int pcm16leToFloat(byte[] in, int inOffset, int byteCount, float[] out, int outOffset) {
        int samples = byteCount / 2;
        for (int i = 0; i < samples; i++) {
            int lo = in[inOffset + 2 * i] & 0xFF;
            int hi = in[inOffset + 2 * i + 1];          // sign-extended on purpose
            out[outOffset + i] = (short) ((hi << 8) | lo) / 32768f;
        }
        return samples;
    }

    /**
     * Averages interleaved channels into one. Returns the input array itself when it is
     * already mono.
     */
    public static float[] mixToMono(float[] interleaved, int channels) {
        if (channels <= 1) {
            return interleaved;
        }
        int frames = interleaved.length / channels;
        float[] mono = new float[frames];
        for (int f = 0; f < frames; f++) {
            float sum = 0;
            for (int c = 0; c < channels; c++) {
                sum += interleaved[f * channels + c];
            }
            mono[f] = sum / channels;
        }
        return mono;
    }

    /**
     * Converts the first {@code count} mono samples from {@code fromRate} to
     * {@code toRate}.
     * <p>
     * Going down, each output sample is the average of the input samples it covers,
     * which doubles as the low-pass filter that down-sampling needs. Going up, samples
     * are linearly interpolated. This is adequate for speech recognition; it is not a
     * studio-quality resampler.
     */
    public static float[] resample(float[] in, int count, float fromRate, float toRate) {
        if (count <= 0) {
            return new float[0];
        }
        if (fromRate == toRate) {
            float[] copy = new float[count];
            System.arraycopy(in, 0, copy, 0, count);
            return copy;
        }

        double ratio = (double) fromRate / toRate;      // input samples per output sample
        int outLength = (int) Math.floor((double) count * toRate / fromRate);
        float[] out = new float[Math.max(outLength, 0)];

        if (ratio > 1.0) {
            for (int i = 0; i < out.length; i++) {
                double start = i * ratio;
                int from = (int) start;
                int to = Math.min(count, Math.max(from + 1, (int) Math.ceil(start + ratio)));
                float sum = 0;
                for (int j = from; j < to; j++) {
                    sum += in[j];
                }
                out[i] = sum / (to - from);
            }
        } else {
            for (int i = 0; i < out.length; i++) {
                double position = i * ratio;
                int left = (int) position;
                int right = Math.min(count - 1, left + 1);
                float fraction = (float) (position - left);
                out[i] = in[left] + (in[right] - in[left]) * fraction;
            }
        }
        return out;
    }
}
