package io.xlogistx.common.http;


import org.zoxweb.server.http.HTTPRawMessage;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.util.*;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class HTTPProtocolHandler
    implements CloseableType, IsExpired
{

    public final LogWrapper log = new LogWrapper(HTTPProtocolHandler.class).setEnabled(false);
    private final UByteArrayOutputStream responseStream = ByteBufferUtil.allocateUBAOS(256);//new UByteArrayOutputStream(256);
    private HTTPMessageConfigInterface response = new HTTPMessageConfig();
    private final HTTPRawMessage rawRequest = new HTTPRawMessage(ByteBufferUtil.allocateUBAOS(256));
    private final AtomicBoolean closed = new AtomicBoolean();
    private volatile URIScheme protocolMode;
    //private volatile Lifetime keepAliveLifetime = null;
    //private Appointment keepAliveAppointment = null;
    private volatile int lastWSIndex = 0;
    private volatile Object extraSession;
    private final KATracker kaTracker;

    //public volatile List<HTTPWSFrame> pendingWSFrames = new ArrayList<HTTPWSFrame>();



    private volatile Object endPointBean = null;


    //public AtomicBoolean isBusy = new AtomicBoolean();


    //private volatile S subject = null;
    private volatile OutputStream outputStream;

    public HTTPProtocolHandler(URIScheme protocol, KAConfig kaConfig)
    {
        switchProtocol(protocol);
        this.kaTracker = new KATracker(kaConfig, this);
    }


    public URIScheme getProtocol()
    {
        return protocolMode;
    }

    public HTTPProtocolHandler switchProtocol(URIScheme protocol)
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



//    private void checkKeepAlive()
//    {
//        // check if we have keep alive configured by the server then
//        // if the incoming request wants it
//        if (!kaTracker.isExpired() &&
//                rawRequest.getHTTPMessageConfig().lookupMatchingHeader(HTTPHeader.CONNECTION, "keep-alive") != null)
//        {
//            if (keepAliveLifetime == null)
//            {
//                // reason for double lock check is speed baby
//                synchronized (this)
//                {
//                    if (keepAliveLifetime == null)
//                    {
//                        NVGenericMap keepAliveConfig = ResourceManager.lookupResource("keep-alive-config");
//                        int maxUse = keepAliveConfig.getValue("maximum");
//                        long timeOut = keepAliveConfig.getValue("time_out");
//                        keepAliveLifetime = new Lifetime(System.currentTimeMillis(), maxUse, null, timeOut);
////                        keepAliveAppointment = TaskUtil.defaultTaskScheduler().queue(keepAliveLifetime.nextWait(), ()->{
////                            if (!isClosed())
////                            {
////                                if(log.isEnabled()) log.getLogger().info(SharedUtil.toCanonicalID(',',  "complete:"+isRequestComplete(), "busy:"+isBusy.get(), rawRequest.getDataStream().size(), keepAliveLifetime));
////                                try
////                                {
////                                    if(!isBusy.get())
////                                        close();
////                                    else
////                                    {
////                                        synchronized (HTTPProtocolHandler.this)
////                                        {
////                                            // situation could occur if the request processing of the client
////                                            // taking longer than expected and we need to close
////                                            // and the keep timeout and keep alive is active
////                                            // very very rare case not sure if it will ever occur
////                                            IOUtil.close(keepAliveAppointment, keepAliveLifetime);
////                                            if(log.isEnabled()) log.getLogger().info("//****************** Very rare case to happen!!!  ******************\\\\");
////                                        }
////                                    }
////                                }
////                                catch (Exception e)
////                                {
////                                    e.printStackTrace();
////                                }
////                            }
////                        });
//                    }
//                }
//            }
//
//            if (!keepAliveLifetime.isClosed())
//                keepAliveAppointment.cancel();
//        }
//        else if (keepAliveLifetime != null)
//           IOUtil.close(keepAliveAppointment, keepAliveLifetime);
//
//
//    }


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
//            isBusy.set(false);
            //IOUtil.close(keepAliveLifetime, keepAliveAppointment);

            if(getExtraSession() instanceof AutoCloseable)
                IOUtil.close((AutoCloseable) getExtraSession(), getOutputStream());
            else
                IOUtil.close(getOutputStream());

            ByteBufferUtil.cache(responseStream, rawRequest.getDataStream());
            expire();
            //if(log.isEnabled()) log.getLogger().info(keepAliveAppointment + " " + keepAliveLifetime + " " + protocolMode);

        }
    }

    public synchronized boolean reset()
    {
        if(!isExpired())
        {
            if (isHTTPProtocol())
            {
                response = new HTTPMessageConfig();
                rawRequest.reset();
                responseStream.reset();
            }
            else if (isWSProtocol())
            {
                rawRequest.reset();
                responseStream.reset();
                setLastWSIndex(0);
            }
            return true;
        }

        return false;
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
        if (getOutputStream() instanceof CloseableType)
            return ((CloseableType) getOutputStream()).isClosed() || closed.get();
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

    @Override
    public synchronized boolean isExpired()
    {
        return kaTracker.isExpired();
    }
    @Override
    public void expire()
    {
        kaTracker.expire();
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

        if (log.isEnabled()) log.getLogger().info( kaTracker.isExpired() + " usage " + kaTracker.lastUsage());
        if (isExpired() || response.getHTTPStatusCode().CODE >= HTTPStatusCode.BAD_REQUEST.CODE)
        {
            //we close the connection
            response.getHeaders().add(HTTPConst.CommonHeader.CONNECTION_CLOSE);
        }
        else
        {
            if (kaTracker.isExpired() ||
                    (isHTTPProtocol() && getRawRequest().getHTTPMessageConfig().lookupMatchingHeader(HTTPHeader.CONNECTION, HTTPHeader.KEEP_ALIVE.getName()) == null))
            {
                if (log.isEnabled()) log.getLogger().info(""  + getRawRequest().getHTTPMessageConfig().lookupMatchingHeader(HTTPHeader.CONNECTION, HTTPHeader.KEEP_ALIVE.getName()));
                expire();
                response.getHeaders().build(HTTPConst.CommonHeader.CONNECTION_CLOSE).remove(HTTPHeader.KEEP_ALIVE);

            }
            else
            {

                // keep not expired
                response.getHeaders().build(HTTPConst.CommonHeader.CONNECTION_KEEP_ALIVE)
                        .build(new NVPair(HTTPHeader.KEEP_ALIVE, "timeout=" + TimeUnit.SECONDS.convert(kaTracker.kaConfig.time_out, TimeUnit.MILLISECONDS) +
                                (kaTracker.kaConfig.max > 0 ? ", max=" + (kaTracker.kaConfig.max - kaTracker.updateUsage()) : "")));
                if (log.isEnabled()) log.getLogger().info( kaTracker.isExpired() + " usage " + kaTracker.lastUsage());
            }
        }
    }


    public <V> V  getEndPointBean() {
        return (V) endPointBean;
    }

    public HTTPProtocolHandler setEndPointBean(Object endPointBean) {
        this.endPointBean = endPointBean;
        return this;
    }

//    public S getSubject()
//    {
//        return subject;
//    }
//
//    public HTTPProtocolHandler<S> setSubject(S subject)
//    {
//        this.subject = subject;
//        return this;
//    }

    public int getLastWSIndex()
    {
        return lastWSIndex;
    }

    public synchronized void setLastWSIndex(int index)
    {
        this.lastWSIndex = index;
    }

}
