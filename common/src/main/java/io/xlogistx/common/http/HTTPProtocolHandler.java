package io.xlogistx.common.http;


import org.zoxweb.server.http.HTTPRawMessage;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.Lifetime;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.util.*;

import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class HTTPProtocolHandler
    implements Closeable, IsClosed
{

    public final LogWrapper log = new LogWrapper(HTTPProtocolHandler.class).setEnabled(false);
    private final UByteArrayOutputStream responseStream = ByteBufferUtil.allocateUBAOS(256);//new UByteArrayOutputStream(256);
    private HTTPMessageConfigInterface response = new HTTPMessageConfig();
    private final HTTPRawMessage rawRequest = new HTTPRawMessage(ByteBufferUtil.allocateUBAOS(256));
    private final AtomicBoolean closed = new AtomicBoolean();
    private final boolean https;
    private Lifetime keepAliveLifetime = null;
    private Appointment keepAliveAppointment = null;


    public AtomicBoolean isBusy = new AtomicBoolean();



    private volatile OutputStream outputStream;

    public HTTPProtocolHandler(boolean https)
    {
        this.https = https;
    }


    public boolean isHTTPs()
    {
        return https;
    }



    public boolean parseRequest(ByteBuffer inBuffer) throws IOException
    {
        ByteBufferUtil.write(inBuffer, rawRequest.getDataStream(), true);

        rawRequest.parse(true);
        boolean ret = rawRequest.isMessageComplete();// ? rawRequest.getHTTPMessageConfig() : null;

        if (ret)
        {
            checkKeepAlive();
        }
        return ret;
    }





    private void checkKeepAlive()
    {
        // check if we have keep alive configured by the server then
        // if the incoming request wants it
        if (ResourceManager.SINGLETON.lookup("keep-alive-config") != null &&
                SharedStringUtil.contains(rawRequest.getHTTPMessageConfig().getHeaders().lookupValue(HTTPHeader.CONNECTION),
            "keep-alive", true))
        {
            if (keepAliveLifetime == null)
            {
                // reason for double lock check is speed baby
                synchronized (this)
                {
                    if (keepAliveLifetime == null)
                    {
                        NVGenericMap keepAliveConfig = ResourceManager.lookupResource("keep-alive-config");
                        int maxUse = keepAliveConfig.getValue("maximum");
                        long timeOut = keepAliveConfig.getValue("time_out");
                        keepAliveLifetime = new Lifetime(System.currentTimeMillis(), maxUse, null, timeOut);
                        keepAliveAppointment = TaskUtil.defaultTaskScheduler().queue(keepAliveLifetime.nextWait(), ()->{
                            if (!isClosed())
                            {
                                if(log.isEnabled()) log.getLogger().info(SharedUtil.toCanonicalID(',',  "complete:"+isRequestComplete(), "busy:"+isBusy.get(), rawRequest.getDataStream().size(), keepAliveLifetime));
                                try
                                {
                                    if(!isBusy.get())
                                        close();
                                    else
                                    {
                                        synchronized (HTTPProtocolHandler.this)
                                        {
                                            // situation could occur if the request processing if the client
                                            // taking longer than expected and we need to close
                                            // and the keep timeout and keep alive is active
                                            // very very rare case not sure if it will ever occur
                                            IOUtil.close(keepAliveAppointment, keepAliveLifetime);
                                            if(log.isEnabled()) log.getLogger().info("//****************** Very rare case to happen!!!  ******************\\\\");
                                        }
                                    }
                                }
                                catch (Exception e)
                                {
                                    e.printStackTrace();
                                }
                            }
                        });
                    }
                }
            }

            if (!keepAliveLifetime.isClosed())
                keepAliveAppointment.cancel();
        }
        else if (keepAliveLifetime != null)
           IOUtil.close(keepAliveAppointment, keepAliveLifetime);


    }


    public boolean isRequestComplete()
    {
        return rawRequest.isMessageComplete();
    }

    public HTTPMessageConfigInterface getRequest()
    {
        return isRequestComplete() ? rawRequest.getHTTPMessageConfig() : null;
    }

    public UByteArrayOutputStream getResponseStream()
    {
        return isRequestComplete() ? responseStream : null;
    }

    @Override
    public synchronized void close() throws IOException
    {
        if(!closed.getAndSet(true))
        {
            isBusy.set(false);
            IOUtil.close(keepAliveLifetime, keepAliveAppointment, getOutputStream());
            ByteBufferUtil.cache(responseStream, rawRequest.getDataStream());
            if(log.isEnabled()) log.getLogger().info(keepAliveAppointment + " " + keepAliveLifetime);
        }
    }

    public synchronized boolean reset()
    {

        if(!isKeepAliveExpired())
        {
            if (keepAliveAppointment.reset(true))
            {
                response = new HTTPMessageConfig();
                rawRequest.reset();
                responseStream.reset();
                keepAliveLifetime.incUsage();
                return true;
            }
        }

        return false;
    }

    public boolean isClosed()
    {
        return closed.get();
    }

    public OutputStream getOutputStream()
    {
        return outputStream;
    }

    public HTTPProtocolHandler setOutputStream(OutputStream os)
    {
        this.outputStream = os;
        return this;
    }

    public synchronized boolean isKeepAliveExpired()
    {
        return keepAliveLifetime == null || keepAliveLifetime.isClosed() || keepAliveAppointment.isClosed();
    }

    public synchronized HTTPMessageConfigInterface buildJSONResponse(Object result, HTTPStatusCode statusCode, GetNameValue<?> ...headersToAdd)
    {
        if (!isRequestComplete())
            throw new IllegalStateException("HTTP request not complete yet");

        HTTPUtil.buildJSONResponse(response, result, statusCode, headersToAdd);
        validateKeepAlive();
        return response;
    }



    public synchronized HTTPMessageConfigInterface buildResponse(HTTPStatusCode statusCode, GetNameValue<?> ...headersToAdd)
    {
        if (!isRequestComplete())
            throw new IllegalStateException("HTTP request not complete yet");

        response.setHTTPStatusCode(statusCode);


        NVGenericMap respHeaders = response.getHeaders();

        if (headersToAdd != null)
        {
            for(GetNameValue<?> header : headersToAdd)
                if(header != null)
                    respHeaders.add(header);
        }

        validateKeepAlive();


        return response;
    }


    private  void validateKeepAlive()
    {
        if (isKeepAliveExpired() || response.getHTTPStatusCode().CODE >= HTTPStatusCode.BAD_REQUEST.CODE)
        {
            //we close the connection
            response.getHeaders().add(HTTPConst.CommonHeader.CONNECTION_CLOSE);
            IOUtil.close(keepAliveLifetime, keepAliveAppointment);
        }
        else
        {
            // keep not expired
            response.getHeaders().build(HTTPConst.CommonHeader.CONNECTION_KEEP_ALIVE)
                    // we keep alive
                    .build(new NVPair(HTTPHeader.KEEP_ALIVE, "timeout=" +  TimeUnit.SECONDS.convert(keepAliveLifetime.getDelayInMillis(),TimeUnit.MILLISECONDS) +
                            (keepAliveLifetime.getMaxUse() > 0 ? ", max=" + (keepAliveLifetime.getMaxUse() - keepAliveLifetime.getUsageCounter()) : "")));
        }
    }

}
