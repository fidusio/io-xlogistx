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
import org.zoxweb.shared.net.InetSocketAddressDAO;
import org.zoxweb.shared.util.*;

import javax.net.ssl.SSLContext;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

public class MiniHTTPServer
    extends SSLSessionCallback
{
    UByteArrayOutputStream ubaos = new UByteArrayOutputStream(256);
    @Override
    public void accept(ByteBuffer inBuffer) {
        // data handling
        if(inBuffer != null)
        {
            try{

                ByteBufferUtil.write(inBuffer, ubaos, true);
                //log.info("incoming data\n" + SharedStringUtil.toString(ubaos.getInternalBuffer(), 0, ubaos.size()));
                HTTPRawMessage hrm = new HTTPRawMessage(ubaos);
                HTTPMessageConfigInterface hmci = hrm.parse(true);


                NVGenericMap nvgm = new NVGenericMap();
                nvgm.add("string", "hello");
                nvgm.add(new NVLong("timestamp", System.currentTimeMillis()));
                nvgm.add(new NVBoolean("bool", true));
                nvgm.add(new NVFloat("float", (float) 12.43534));

                HTTPUtil.formatResponse(HTTPUtil.formatResponse(nvgm, HTTPStatusCode.OK), ubaos);

                get().write(ubaos.getInternalBuffer(), 0, ubaos.size());

//                ByteBufferUtil.write(ubaos, config.outAppData);

                //log.info("data to be sent \n" + SharedStringUtil.toString(ubaos.getInternalBuffer(), 0, ubaos.size()));
//                get().write(config.outAppData);

            }
            catch(Exception e)
            {
                e.printStackTrace();
                log.info(""+e);
                // we should close

            }
            finally {
                IOUtil.close(get());
            }

        }

    }

    public static void main(String ...args)
    {
        TaskUtil.setThreadMultiplier(8);
        TaskUtil.setMaxTasksQueue(2048);
        LoggerUtil.enableDefaultLogger("io.xlogistx");
        try
        {
            //SSLContext clientContext = SSLContext.getInstance("TLS",new BouncyCastleProvider());
            //Security.addProvider(new BouncyCastleJsseProvider());
            int index = 0;
            int port = Integer.parseInt(args[index++]);
            String keystore = args[index++];
            String ksType = args[index++];
            String ksPassword = args[index++];
            InetSocketAddressDAO remoteAddress = index < args.length ? new InetSocketAddressDAO(args[index++]) : null;
            boolean dbg = (index < args.length);
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

            new NIOSocket(new InetSocketAddress(port), 256, new SSLNIOSocketFactory(sslContext, MiniHTTPServer.class), TaskUtil.getDefaultTaskProcessor());
        }
        catch(Exception e)
        {
            e.printStackTrace();
            TaskUtil.getDefaultTaskScheduler().close();
            TaskUtil.getDefaultTaskProcessor().close();
        }
    }


}
