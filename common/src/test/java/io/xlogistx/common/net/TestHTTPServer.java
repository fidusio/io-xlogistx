package io.xlogistx.common.net;

import io.xlogistx.common.http.URIMap;
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
import java.util.concurrent.atomic.AtomicLong;

public class TestHTTPServer
extends PlainSessionCallback
{
    public static boolean debug = false;
    public final static AtomicLong time = new AtomicLong(0);
    public final static AtomicLong counter = new AtomicLong(0);
    //UByteArrayOutputStream ubaos = new UByteArrayOutputStream(256);
    final static AtomicLong ts =  new AtomicLong(0);
    final static URIMap<String> uriMap = new URIMap<>();

    HTTPRawMessage hrm = new HTTPRawMessage(new UByteArrayOutputStream(256));
    @Override
    public void accept(ByteBuffer inBuffer) {
        // data handling
        //String msg = "" + inBuffer;
        if( ts.get() == 0 )
        {
            synchronized (ts)
            {
                if (ts.get() == 0)
                {
                    ts.set(System.nanoTime());
                }
            }
        }
        UByteArrayOutputStream resp = null;

        if (inBuffer != null)
        {
            try
            {

               ByteBufferUtil.write(inBuffer, hrm.getUBAOS(), true);

                HTTPMessageConfigInterface hmci = hrm.parse(true);

                if(hrm.isMessageComplete())
                {
                    String match = uriMap.lookup(hmci.getURI());

                    if (debug) {
                        log.info("incoming data\n" + SharedStringUtil.toString(hrm.getUBAOS().getInternalBuffer(), 0, hrm.getUBAOS().size()));
                        log.info("" + hmci);
                        log.info("uriMatch : "+ match);
                    }

                    if (match != null)
                    {
                        NVGenericMap nvgm = new NVGenericMap();
                        nvgm.add("string", "hello");
                        nvgm.add(new NVLong("timestamp", System.currentTimeMillis()));
                        nvgm.add(new NVBoolean("bool", true));
                        nvgm.add(new NVFloat("float", (float) 12.43534));
                        resp = HTTPUtil.formatResponse(HTTPUtil.formatResponse(nvgm, HTTPStatusCode.OK), hrm.getUBAOS());
                    }
                    else
                    {
                        resp = HTTPUtil.formatResponse(HTTPUtil.formatResponse(HTTPStatusCode.NOT_FOUND), hrm.getUBAOS());
                    }
                    get().write(resp.getInternalBuffer(), 0, resp.size());
                    IOUtil.close(get());

                    if (counter.incrementAndGet() %1000 == 0) {
                        long sample = System.nanoTime();
                        time.addAndGet(sample - ts.get());
                        ts.set(0);
                    }
                    if (debug)
                        log.info("data to be sent \n" + SharedStringUtil.toString(resp.getInternalBuffer(), 0, resp.size()));
                }
                else
                {
                    log.info("Message not complete yet");
                }




            }
            catch (Exception e)
            {
                e.printStackTrace();
                log.info("" + e + " "  + " " + ((ChannelOutputStream)get()).outAppData + " " + resp);
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

            String[] uris ={
              "/timestamp",
              "/ping",
              "/stats/detailed"
            };
            for(String uri : uris)
            {
                uriMap.put(uri, uri);
            }



            new NIOSocket(new InetSocketAddress(port), 128, new NIOPlainSocketFactory(TestHTTPServer.class), TaskUtil.getDefaultTaskProcessor());
            TaskUtil.getDefaultTaskScheduler().queue(Const.TimeInMillis.SECOND.MILLIS * 30, new Runnable() {
                @Override
                public void run() {
                    long c = counter.get();
                    long nanos = time.get();
                    float rate = (float)c/(float)nanos;
                    log.info("rate: " + rate*1000000000);
                    log.info("nanos: " + Const.TimeInMillis.nanosToString(nanos) + " count: " + c);
                    TaskUtil.getDefaultTaskScheduler().queue(Const.TimeInMillis.SECOND.MILLIS*30, this);
            }});
        }
        catch(Exception e)
        {
            e.printStackTrace();
            TaskUtil.getDefaultTaskScheduler().close();
            TaskUtil.getDefaultTaskProcessor().close();
        }
    }
}
