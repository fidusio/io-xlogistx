package io.xlogistx.crypto;

import org.junit.jupiter.api.Test;
import org.zoxweb.shared.util.BytesValue;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.SharedStringUtil;


import java.security.NoSuchAlgorithmException;


public class DigestAppenderTest {
    @Test
    public void digestAppender() throws NoSuchAlgorithmException {
        DigestAppender da = new DigestAppender("sha-256");


        for (int i=0; i < 10; i++)
        {
            long nanos = System.nanoTime();
            byte[] result = da.append(BytesValue.INT.toBytes(i));
            nanos = System.nanoTime() - nanos;
            System.out.println(SharedStringUtil.bytesToHex(result) + " it took " + Const.TimeInMillis.nanosToString(nanos));

        }
    }
}
