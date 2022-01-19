package io.xlogistx.ssl;

import io.xlogistx.common.fsm.StateMachine;
import io.xlogistx.common.fsm.TriggerConsumer;
import org.zoxweb.server.http.HTTPRawMessage;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.server.logging.LoggerUtil;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;
import org.zoxweb.shared.http.HTTPStatusCode;

import org.zoxweb.shared.util.*;

import javax.net.ssl.SSLContext;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

public class SSLTestHTTPServer
    extends SSLSessionCallback
{
    public static boolean debug = false;
    UByteArrayOutputStream ubaos = new UByteArrayOutputStream(256);
    HTTPRawMessage hrm = new HTTPRawMessage(ubaos);
    public void accept(ByteBuffer inBuffer) {
        // data handling
        String msg = "" + inBuffer;
        UByteArrayOutputStream resp = null;
        if (inBuffer != null) {
            try {

                ByteBufferUtil.write(inBuffer, ubaos, true);
//                if (debug)
//                    log.info("incoming data\n" + SharedStringUtil.toString(ubaos.getInternalBuffer(), 0, ubaos.size()));
                HTTPMessageConfigInterface hmci = hrm.parse(true);
                if(hrm.isMessageComplete())
                {
                    NVGenericMap nvgm = new NVGenericMap();
                    nvgm.add("string", "hello");
                    nvgm.add(new NVLong("timestamp", System.currentTimeMillis()));
                    nvgm.add(new NVBoolean("bool", true));
                    nvgm.add(new NVFloat("float", (float) 12.43534));

                    resp = HTTPUtil.formatResponse(HTTPUtil.formatResponse(nvgm, HTTPStatusCode.OK), ubaos);

                    get().write(resp.getInternalBuffer(), 0, resp.size());
                    IOUtil.close(get());
                }
                else
                {
                    log.info("Message not complete yet");
                }

//                if (debug)
//                    log.info("data to be sent \n" + SharedStringUtil.toString(ubaos.getInternalBuffer(), 0, ubaos.size()));


            } catch (Exception e) {
                e.printStackTrace();
                log.info("" + e + " " + msg  + " " + resp);
                IOUtil.close(get());
                // we should close
            }
            //log.info(""+ ByteBufferUtil.cacheCount() + ", " + ByteBufferUtil.cacheCapacity());
        }
    }

    public static void main(String ...args)
    {
        TaskUtil.setThreadMultiplier(8);
        TaskUtil.setMaxTasksQueue(2048);
        LoggerUtil.enableDefaultLogger("io.xlogistx");
        try
        {

            ParamUtil.ParamMap params = ParamUtil.parse("-", args);
            int port = params.intValue("-port");
            String keystore = params.stringValue("-keystore");
            String ksType = params.stringValue("-kstype");
            String ksPassword = params.stringValue("-kspassword");
            boolean dbg = params.nameExists("-dbg");
            if(dbg)
            {
                SSLStateMachine.debug = true;
                ReadyState.debug = true;
                HandshakingState.debug = true;
                StateMachine.debug = true;
                TriggerConsumer.debug = true;

            }
            else
            {
                SSLSessionConfig.debug = false;
            }



            //TaskUtil.setThreadMultiplier(4);
            SSLContext sslContext = CryptoUtil.initSSLContext(null, null, IOUtil.locateFile(keystore), ksType, ksPassword.toCharArray(), null, null ,null);

            new NIOSocket(new InetSocketAddress(port), 256, new SSLNIOSocketFactory(sslContext, SSLTestHTTPServer.class), TaskUtil.getDefaultTaskProcessor());
        }
        catch(Exception e)
        {

            e.printStackTrace();
            TaskUtil.getDefaultTaskScheduler().close();
            TaskUtil.getDefaultTaskProcessor().close();
            System.err.println("-port 8443 -keystore web.xlogistx.io.jks -kstype pkcs12 -kspassword password -ra 10.0.0.1:80");
        }
    }


}
