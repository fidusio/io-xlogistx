package io.xlogistx.common.test;

import io.xlogistx.common.image.ImageInfo;
import io.xlogistx.common.image.TextToImage;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.SharedStringUtil;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.UUID;

public class TextToImageTest {
    public static void main(String[] args) throws Exception
    {

        SecureRandom sr = new SecureRandom();
        ImageInfo ii = null;
        int len = Integer.parseInt(args[0]);
        try {
            for (int i = 0; i < len; i++) {
                long ts = System.nanoTime();
                int num = Math.abs(sr.nextInt() % 100000);

                String text = SharedStringUtil.spaceChars("" + num, SharedStringUtil.repeatSequence(" ", num % 4));
                ii = TextToImage.textToImage(text, "gif", new Font("Arial", Font.ITALIC, 18), Color.GREEN, UUID.randomUUID().toString());


                ts = System.nanoTime()- ts;
                System.out.println("w: " + ii.width + " h: " + ii.height + " bytes : " + ii.data.available() + " " + Const.TimeInMillis.nanosToString(ts) + " : " + text);

            }


            IOUtil.relayStreams(ii.data, new FileOutputStream("D:/Sample."+ii.format), true);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }
}
