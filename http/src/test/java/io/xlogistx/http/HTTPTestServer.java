package io.xlogistx.http;

import io.xlogistx.common.http.URIMap;
import io.xlogistx.common.net.NIOPlainSocketFactory;
import io.xlogistx.common.net.PlainSessionCallback;
import io.xlogistx.common.http.HTTPProtocolHandler;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.server.logging.LoggerUtil;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.data.CurrentTimestamp;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.util.*;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicLong;

public class HTTPTestServer
extends PlainSessionCallback
{
    public static boolean debug = true;
    private static RateCounter messages = new RateCounter("UnsecureMessages");
    final  AtomicLong ts =  new AtomicLong(0);
    final static URIMap<String> uriMap = new URIMap<>();
    private final HTTPProtocolHandler hph = new HTTPProtocolHandler();


    @Override
    public void accept(ByteBuffer inBuffer) {
        if(ts.get() == 0)
        {
            ts.set(System.nanoTime());
        }


        UByteArrayOutputStream resp = null;

        if (inBuffer != null)
        {
            try
            {

                if(hph.parseRequest(inBuffer))
                {
                    String match = uriMap.lookup(hph.getHTTPMessage().getURI());

                    if (debug) {
                        log.info("incoming data\n" + SharedStringUtil.toString(hph.getRawRequest().getInternalBuffer(), 0, hph.getRawRequest().size()));
                        log.info("MESSAGE INFO : " + hph.getHTTPMessage().getParameters());
                        log.info("uriMatch : "+ match);
                    }

                    if (match != null)
                    {
                        CurrentTimestamp ct = new CurrentTimestamp();
                        resp = HTTPUtil.formatResponse(HTTPUtil.formatResponse(ct, HTTPStatusCode.OK), hph.getRawResponse());
                    }
                    else
                    {
                        resp = HTTPUtil.formatResponse(HTTPUtil.formatResponse(HTTPStatusCode.NOT_FOUND), hph.getRawResponse());
                    }
                    get().write(resp.getInternalBuffer(), 0, resp.size());
                    IOUtil.close(get());

                    messages.register(System.nanoTime() - ts.get());


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
                log.info("" + e + " "  + " " + get()+ " " + resp);
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

            for(int i = 0; i < 1000; i++)
            {
                uriMap.put("/dummy"+i, "/dummy"+i);
            }
            log.info("Total URIs: " + uriMap.size());



            new NIOSocket(new InetSocketAddress(port), 128, new NIOPlainSocketFactory(HTTPTestServer.class), TaskUtil.getDefaultTaskProcessor());
            TaskUtil.getDefaultTaskScheduler().queue(Const.TimeInMillis.SECOND.MILLIS * 30, new Runnable() {
                @Override
                public void run() {

                    log.info("rate: " + messages.rate(1000000000));
                    log.info("nanos: " + Const.TimeInMillis.nanosToString(messages.getDeltas()) + " count: " + messages.getCounts());
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
