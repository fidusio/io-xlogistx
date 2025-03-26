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
import org.zoxweb.shared.protocol.HTTPWSFrame;
import org.zoxweb.shared.util.*;

import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class HTTPProtocolHandler<S>
    implements Closeable, IsClosed
{

    public final LogWrapper log = new LogWrapper(HTTPProtocolHandler.class).setEnabled(false);
    private final UByteArrayOutputStream responseStream = ByteBufferUtil.allocateUBAOS(256);//new UByteArrayOutputStream(256);
    private HTTPMessageConfigInterface response = new HTTPMessageConfig();
    private final HTTPRawMessage rawRequest = new HTTPRawMessage(ByteBufferUtil.allocateUBAOS(256));
    private final AtomicBoolean closed = new AtomicBoolean();
    private volatile URIScheme protocolMode;
    private Lifetime keepAliveLifetime = null;
    private Appointment keepAliveAppointment = null;
    private volatile int lastWSIndex = 0;
    private volatile Object extraSession;

    public volatile List<HTTPWSFrame> pendingWSFrames = new ArrayList<HTTPWSFrame>();



    private volatile Object endPointBean = null;


    public AtomicBoolean isBusy = new AtomicBoolean();


    private volatile S subject = null;
    private volatile OutputStream outputStream;

    public HTTPProtocolHandler(URIScheme protocol)
    {
        switchProtocol(protocol);
    }


    public URIScheme getProtocol()
    {
        return protocolMode;
    }

    public HTTPProtocolHandler<S> switchProtocol(URIScheme protocol)
    {
        switch (protocol)
        {
            case HTTPS:
            case HTTP:
            case WSS:
            case WS:
                this.protocolMode = protocol;
                break;
            default:
                throw new UnsupportedOperationException("Unsupported protocol " + protocolMode);
        }
        return this;
    }



    public boolean parseRequest(ByteBuffer inBuffer) throws IOException
    {

        ByteBufferUtil.write(inBuffer, rawRequest.getDataStream(), true);
        switch(protocolMode)
        {
            case HTTP:
            case HTTPS:
                rawRequest.parse(true);
                boolean ret = rawRequest.isMessageComplete();// ? rawRequest.getHTTPMessageConfig() : null;

                if (ret)
                {
                    checkKeepAlive();
                }
                if (log.isEnabled()) log.getLogger().info("Protocol Mode: " + protocolMode + " message complete " + ret);
                return ret;
            case WS:
            case WSS:
                // to be added here
                return true;
            default:
                throw new IllegalStateException("Unexpected value: " + protocolMode);
        }
    }

    public HTTPRawMessage getRawRequest()
    {
        return rawRequest;
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
        return getResponseStream( false);
    }

    public UByteArrayOutputStream getResponseStream(boolean override)
    {
        return override || isRequestComplete() ? responseStream : null;
    }

    @Override
    public synchronized void close() throws IOException
    {
        if(!closed.getAndSet(true))
        {
            isBusy.set(false);
            IOUtil.close(keepAliveLifetime, keepAliveAppointment, getOutputStream());
            ByteBufferUtil.cache(responseStream, rawRequest.getDataStream());
            if(log.isEnabled()) log.getLogger().info(keepAliveAppointment + " " + keepAliveLifetime + " " + protocolMode);

            if(getExtraSession() instanceof AutoCloseable)
                IOUtil.close((AutoCloseable) getExtraSession());
        }
    }

    public synchronized boolean reset()
    {

        if(isHTTPProtocol() && !isKeepAliveExpired())
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
        else if (isWSProtocol())
        {
            rawRequest.reset();
            responseStream.reset();
            setLastWSIndex(0);
            keepAliveLifetime = null;
        }

        return isWSProtocol();
    }


    public boolean isHTTPProtocol()
    {
        return (protocolMode == URIScheme.HTTPS || protocolMode == URIScheme.HTTP);
    }
    public boolean isWSProtocol()
    {
        return (protocolMode == URIScheme.WSS || protocolMode == URIScheme.WS);
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

    public void setExtraSession(Object extraSession)
    {
        this.extraSession = extraSession;
    }

    public <V> V getExtraSession()
    {
        return (V)extraSession;
    }

//    public synchronized HTTPMessageConfigInterface buildJSONResponse(Object result, HTTPStatusCode statusCode, GetNameValue<?> ...headersToAdd)
//    {
//        if (!isRequestComplete())
//            throw new IllegalStateException("HTTP request not complete yet");
//
//        HTTPUtil.buildJSONResponse(response, result, statusCode, headersToAdd);
//        validateKeepAlive();
//        return response;
//    }


    public synchronized HTTPMessageConfigInterface buildResponse(String contentType, Object result, HTTPStatusCode statusCode, GetNameValue<?> ...headersToAdd)
    {
        if (!isRequestComplete())
            throw new IllegalStateException("HTTP request not complete yet");

        response.setContentType(contentType);
        // json response
        if(SharedStringUtil.contains(contentType, "application/json", true))
            HTTPUtil.buildJSONResponse(response, result, statusCode, headersToAdd);
        else
        {
            if (result instanceof String) {
                HTTPUtil.buildResponse(response, statusCode, headersToAdd);
                response.setContent((String) result);
            }
            else if (result instanceof byte[]) {
                HTTPUtil.buildResponse(response, statusCode, headersToAdd);
                response.setContent((byte[]) result);
            }
            else if (result != null)
            {
                // look for encoder for the time being stick with json
                HTTPUtil.buildJSONResponse(response, result, statusCode, headersToAdd);
            }
            else
            {
                HTTPUtil.buildResponse(response, statusCode, headersToAdd);
            }

        }

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


    public <V> V  getEndPointBean() {
        return (V) endPointBean;
    }

    public HTTPProtocolHandler setEndPointBean(Object endPointBean) {
        this.endPointBean = endPointBean;
        return this;
    }

    public S getSubject()
    {
        return subject;
    }

    public HTTPProtocolHandler<S> setSubject(S subject)
    {
        this.subject = subject;
        return this;
    }

    public int getLastWSIndex()
    {
        return lastWSIndex;
    }

    public synchronized void setLastWSIndex(int index)
    {
        this.lastWSIndex = index;
    }

}
