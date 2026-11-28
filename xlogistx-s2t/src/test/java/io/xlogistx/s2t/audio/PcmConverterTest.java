package io.xlogistx.s2t.audio;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;

class PcmConverterTest {

    @Test
    void pcm16LittleEndianBecomesFloatsBetweenMinusOneAndOne() {
        byte[] pcm = {
                0x00, 0x00,                 // 0
                (byte) 0xFF, 0x7F,          // 32767
                0x00, (byte) 0x80,          // -32768
                0x00, 0x40,                 // 16384
                (byte) 0xFF, (byte) 0xFF    // -1
        };
        float[] out = new float[5];

        assertEquals(5, PcmConverter.pcm16leToFloat(pcm, 0, pcm.length, out, 0));
        assertArrayEquals(new float[]{0f, 32767 / 32768f, -1f, 0.5f, -1 / 32768f}, out, 1e-7f);
    }

    @Test
    void pcm16HonoursOffsetsAndIgnoresATrailingOddByte() {
        byte[] pcm = {0x11, 0x00, 0x40, 0x00, (byte) 0xC0, 0x7F};
        float[] out = {9f, 9f, 9f};

        assertEquals(1, PcmConverter.pcm16leToFloat(pcm, 1, 3, out, 1));
        assertArrayEquals(new float[]{9f, 0.5f, 9f}, out, 1e-7f);
    }

    @Test
    void stereoIsAveragedToMonoAndMonoIsReturnedUntouched() {
        float[] stereo = {0.2f, 0.4f, -1f, 1f, 0.5f, 0.5f};
        assertArrayEquals(new float[]{0.3f, 0f, 0.5f}, PcmConverter.mixToMono(stereo, 2), 1e-6f);

        float[] mono = {0.1f, 0.2f};
        assertSame(mono, PcmConverter.mixToMono(mono, 1));
    }

    @Test
    void downsamplingBy3AveragesEachGroupOfThree() {
        float[] in = {0f, 3f, 6f, 1f, 1f, 1f, -3f, 0f, 3f};
        float[] out = PcmConverter.resample(in, in.length, 48_000f, 16_000f);
        assertArrayEquals(new float[]{3f, 1f, 0f}, out, 1e-6f);
    }

    @Test
    void oneSecondAtAnyRateBecomesOneSecondAt16k() {
        assertEquals(16_000, PcmConverter.resample(new float[48_000], 48_000, 48_000f, 16_000f).length);
        assertEquals(16_000, PcmConverter.resample(new float[44_100], 44_100, 44_100f, 16_000f).length);
        assertEquals(16_000, PcmConverter.resample(new float[8_000], 8_000, 8_000f, 16_000f).length);
    }

    @Test
    void upsamplingInterpolatesBetweenNeighbours() {
        float[] out = PcmConverter.resample(new float[]{0f, 1f}, 2, 8_000f, 16_000f);
        assertArrayEquals(new float[]{0f, 0.5f, 1f, 1f}, out, 1e-6f);
    }

    @Test
    void sameRateReturnsACopyOfOnlyTheCountedSamples() {
        float[] in = {1f, 2f, 3f};
        float[] out = PcmConverter.resample(in, 2, 16_000f, 16_000f);
        assertArrayEquals(new float[]{1f, 2f}, out, 0f);
        assertNotSame(in, out);
        assertEquals(0, PcmConverter.resample(in, 0, 48_000f, 16_000f).length);
    }
}
