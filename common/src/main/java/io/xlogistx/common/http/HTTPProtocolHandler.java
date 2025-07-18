package io.xlogistx.common.http;


import org.zoxweb.server.http.HTTPRawMessage;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.protocol.ProtoSession;
import org.zoxweb.shared.util.*;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class HTTPProtocolHandler
        implements CloseableType, IsExpired {

    public final LogWrapper log = new LogWrapper(HTTPProtocolHandler.class).setEnabled(false);
    private final UByteArrayOutputStream responseStream = ByteBufferUtil.allocateUBAOS(256);//new UByteArrayOutputStream(256);
    private HTTPMessageConfigInterface response = new HTTPMessageConfig();
    private final HTTPRawMessage rawRequest = new HTTPRawMessage(ByteBufferUtil.allocateUBAOS(256));
    private final AtomicBoolean closed = new AtomicBoolean();
    private volatile URIScheme protocolMode;
    private volatile int markerIndex = 0;
    private volatile ProtoSession<?, ?> connectionSession;
    private final KATracker kaTracker;
    private volatile Object endPointBean = null;
    private volatile OutputStream outputStream;

    public HTTPProtocolHandler(URIScheme protocol, KAConfig kaConfig) {
        switchProtocol(protocol);
        this.kaTracker = new KATracker(kaConfig, this);
    }


    public URIScheme getProtocol() {
        return protocolMode;
    }

    public HTTPProtocolHandler switchProtocol(URIScheme protocol) {
        switch (protocol) {
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


    public boolean parseRequest(ByteBuffer inBuffer) throws IOException {

        ByteBufferUtil.write(inBuffer, rawRequest.getDataStream(), true);
        switch (protocolMode) {
            case HTTP:
            case HTTPS:
                HTTPMessageConfigInterface hmci = rawRequest.parse();
                boolean ret = rawRequest.isMessageComplete();// ? rawRequest.getHTTPMessageConfig() : null;
                if (!ret && rawRequest.areHeadersParsed() && hmci.isTransferChunked()) {
                    ret = true;
                }
                if (log.isEnabled())
                    log.getLogger().info("Protocol Mode: " + protocolMode + " message complete " + ret);
                return ret;
            case WS:
            case WSS:
                // to be added here
                return true;
            default:
                throw new IllegalStateException("Unexpected value: " + protocolMode);
        }
    }


    public HTTPRawMessage getRawRequest() {
        return rawRequest;
    }


    public boolean isRequestComplete() {
        return rawRequest.isMessageComplete();
    }

    public HTTPMessageConfigInterface getRequest(boolean withIncompleteContent) {
        return withIncompleteContent ? (rawRequest.areHeadersParsed() ? rawRequest.getHTTPMessageConfig() : null) : getRequest();
    }

    public HTTPMessageConfigInterface getRequest() {
        return isRequestComplete() ? rawRequest.getHTTPMessageConfig() : null;
    }

    public UByteArrayOutputStream getResponseStream() {
        return getResponseStream(false);
    }

    public UByteArrayOutputStream getResponseStream(boolean override) {
        return override || isRequestComplete() ? responseStream : null;
    }

    @Override
    public synchronized void close() throws IOException {
        if (!closed.getAndSet(true)) {
            IOUtil.close(getConnectionSession(), getOutputStream());
            ByteBufferUtil.cache(responseStream, rawRequest.getDataStream());
            expire();
        }
    }

    public synchronized boolean reset() {
        if (!isExpired()) {
            if (isHTTPProtocol()) {
                response = new HTTPMessageConfig();
                rawRequest.reset(true);
                responseStream.reset();
            } else if (isWSProtocol()) {
                rawRequest.reset(false);
                responseStream.reset();
                setMarkerIndex(0);
            }
            return true;
        }

        return false;
    }


    public boolean isHTTPProtocol() {
        return (protocolMode == URIScheme.HTTPS || protocolMode == URIScheme.HTTP);
    }

    public boolean isWSProtocol() {
        return (protocolMode == URIScheme.WSS || protocolMode == URIScheme.WS);
    }


    public boolean isClosed() {
        if (getOutputStream() instanceof CloseableType)
            return ((CloseableType) getOutputStream()).isClosed() || closed.get();
        return closed.get();
    }

    public OutputStream getOutputStream() {
        return outputStream;
    }

    public HTTPProtocolHandler setOutputStream(OutputStream os) {
        this.outputStream = os;
        return this;
    }

    @Override
    public synchronized boolean isExpired() {
        return kaTracker.isExpired();
    }

    @Override
    public void expire() {
        kaTracker.expire();
    }

    public synchronized void setConnectionSession(ProtoSession<?, ?> session) {
        this.connectionSession = session;
        if (session != null)
            session.getAutoCloseables().add(this);
    }

    public <V> V getConnectionSession() {
        return (V) connectionSession;
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


    public synchronized HTTPMessageConfigInterface buildResponse(String contentType, Object result, HTTPStatusCode statusCode, GetNameValue<?>... headersToAdd) {
        if (!isRequestComplete())
            throw new IllegalStateException("HTTP request not complete yet");

        if (result instanceof HTTPMessageConfigInterface)
            response = (HTTPMessageConfigInterface) result;
            // json response
        else if (SharedStringUtil.contains(contentType, "application/json", true) && result != null)
            HTTPUtil.buildJSONResponse(response, result, statusCode, headersToAdd);
        else if (result instanceof String) {
            HTTPUtil.buildResponse(response, statusCode, headersToAdd);
            response.setContent((String) result);
        } else if (result instanceof byte[]) {
            HTTPUtil.buildResponse(response, statusCode, headersToAdd);
            response.setContent((byte[]) result);
        } else if (result != null) {
            // look for encoder for the time being stick with json
            HTTPUtil.buildJSONResponse(response, result, statusCode, headersToAdd);
        } else if (result == null) {
            HTTPUtil.buildResponse(response, statusCode, headersToAdd);
            if (response.getHTTPStatusCode() != HTTPStatusCode.NO_CONTENT)
                response.setContentLength(0);
            response.getHeaders().remove(HTTPHeader.CONTENT_TYPE);
//            response.setContentType((GetValue<String>[]) null);
        }


        if (result != null && response.getContentType() == null)
            response.setContentType(contentType);
        validateKeepAlive();
        return response;
    }


    public synchronized HTTPMessageConfigInterface buildResponse(HTTPStatusCode statusCode, GetNameValue<?>... headersToAdd) {
        if (!isRequestComplete())
            throw new IllegalStateException("HTTP request not complete yet");

        response.setHTTPStatusCode(statusCode);


        NVGenericMap respHeaders = response.getHeaders();

        if (headersToAdd != null) {
            for (GetNameValue<?> header : headersToAdd)
                if (header != null)
                    respHeaders.add(header);
        }

        validateKeepAlive();

        return response;
    }


    private void validateKeepAlive() {

        if (log.isEnabled()) log.getLogger().info(kaTracker.isExpired() + " usage " + kaTracker.lastUsage());
        if (isExpired() || response.getHTTPStatusCode().CODE >= HTTPStatusCode.BAD_REQUEST.CODE) {
            //we close the connection
            response.getHeaders().add(HTTPConst.CommonHeader.CONNECTION_CLOSE);
        } else {
            if (kaTracker.isExpired() ||
                    (isHTTPProtocol() && getRawRequest().getHTTPMessageConfig().lookupMatchingHeader(HTTPHeader.CONNECTION, HTTPHeader.KEEP_ALIVE.getName()) == null)) {
                if (log.isEnabled())
                    log.getLogger().info("" + getRawRequest().getHTTPMessageConfig().lookupMatchingHeader(HTTPHeader.CONNECTION, HTTPHeader.KEEP_ALIVE.getName()));
                expire();
                response.getHeaders().build(HTTPConst.CommonHeader.CONNECTION_CLOSE).remove(HTTPHeader.KEEP_ALIVE);

            } else {

                // keep not expired
                response.getHeaders().build(HTTPConst.CommonHeader.CONNECTION_KEEP_ALIVE)
                        .build(new NVPair(HTTPHeader.KEEP_ALIVE, "timeout=" + TimeUnit.SECONDS.convert(kaTracker.kaConfig.time_out, TimeUnit.MILLISECONDS) +
                                (kaTracker.kaConfig.max > 0 ? ", max=" + (kaTracker.kaConfig.max - kaTracker.updateUsage()) : "")));
                if (log.isEnabled()) log.getLogger().info(kaTracker.isExpired() + " usage " + kaTracker.lastUsage());
            }
        }
    }


    public <V> V getEndPointBean() {
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

    public int getMarkerIndex() {
        return markerIndex;
    }

    public synchronized void setMarkerIndex(int index) {
        this.markerIndex = index;
    }

}
