package io.xlogistx.common.net;

import org.zoxweb.server.http.HTTPRawMessage;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.server.logging.LoggerUtil;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.util.*;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

public class SimpleHTTPServer
extends PlainSessionCallback
{
    public static boolean debug = false;
    UByteArrayOutputStream ubaos = new UByteArrayOutputStream(256);
    HTTPRawMessage hrm = new HTTPRawMessage(ubaos);
    @Override
    public void accept(ByteBuffer inBuffer) {
        // data handling
        String msg = "" + inBuffer;
        UByteArrayOutputStream resp = null;
        if (inBuffer != null) {
            try {

               ByteBufferUtil.write(inBuffer, ubaos, true);
                if (debug)
                    log.info("incoming data\n" + SharedStringUtil.toString(ubaos.getInternalBuffer(), 0, ubaos.size()));
                HTTPMessageConfigInterface hmci = hrm.parse(true);
                if(hmci != null)
                {


                    NVGenericMap nvgm = new NVGenericMap();
                    nvgm.add("string", "hello");
                    nvgm.add(new NVLong("timestamp", System.currentTimeMillis()));
                    nvgm.add(new NVBoolean("bool", true));
                    nvgm.add(new NVFloat("float", (float) 12.43534));

                    resp = HTTPUtil.formatResponse(HTTPUtil.formatResponse(nvgm, HTTPStatusCode.OK), null);

                    get().write(resp.getInternalBuffer(), 0, resp.size());
                    IOUtil.close(get());
                }
//                else
//                    log.info("MISSING message");

//                ByteBufferUtil.write(ubaos, config.outAppData);

                if (debug)
                    log.info("data to be sent \n" + SharedStringUtil.toString(ubaos.getInternalBuffer(), 0, ubaos.size()));
//                get().write(config.outAppData);

            } catch (Exception e) {
                e.printStackTrace();
                log.info("" + e + " " + msg + " " + ((ChannelOutputStream)get()).outAppData + " " + resp);
                IOUtil.close(get());
                // we should close

            }

        }
    }


    public static void main(String... args)
    {
        LoggerUtil.enableDefaultLogger("io.xlogistx");
        try
        {
            int index = 0;
            int port = Integer.parseInt(args[index++]);

            //TaskUtil.setThreadMultiplier(8);


            new NIOSocket(new InetSocketAddress(port), 128, new NIOPlainSocketFactory(SimpleHTTPServer.class), TaskUtil.getDefaultTaskProcessor());
        }
        catch(Exception e)
        {
            e.printStackTrace();
            TaskUtil.getDefaultTaskScheduler().close();
            TaskUtil.getDefaultTaskProcessor().close();
        }
    }
}
