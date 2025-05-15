package io.xlogistx.common.http;

public class KAConfig {
    public final int max;
    // in millis
    public final long time_out;


    public KAConfig(int max, long timeout) {
        this.max = max;
        this.time_out = timeout;
    }

    @Override
    public String toString() {
        return "KAConfig{" +
                "max=" + max +
                ", time_out=" + time_out +
                '}';
    }
}
