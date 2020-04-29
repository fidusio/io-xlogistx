package io.xlogistx.http.handler;

import com.sun.net.httpserver.HttpExchange;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.data.SimpleMessage;
import org.zoxweb.shared.http.HTTPHeaderName;
import org.zoxweb.shared.http.HTTPMimeType;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.util.SharedStringUtil;

import java.io.IOException;

@SuppressWarnings("restriction")
public class HTTPHandlerUtil {

  private HTTPHandlerUtil()
  {
    
  }
  
  public static void sendErrorMessage(HttpExchange he, HTTPStatusCode hsc, String msg) throws IOException
  {
    SimpleMessage sem = new SimpleMessage(msg, hsc.CODE, hsc.REASON);
    sem.setCreationTime(System.currentTimeMillis());
    sendSimpleMessage(he, hsc, sem);
  }
  
  public static void sendSimpleMessage(HttpExchange he, HTTPStatusCode hsc, SimpleMessage simpleMessage) throws IOException
  {
    String message = GSONUtil.toJSON(simpleMessage, false, false, false);
    byte buffer[] = SharedStringUtil.getBytes(message);
    he.getResponseHeaders().add(HTTPHeaderName.CONTENT_TYPE.getName(), HTTPMimeType.APPLICATION_JSON.getValue());
    he.getResponseHeaders().add(HTTPHeaderName.CONTENT_TYPE.getName(), "charset=utf-8");
    he.sendResponseHeaders(hsc.CODE, buffer.length);
    he.getResponseBody().write(buffer);
  }


  public static void sendJSONResponse(HttpExchange he, HTTPStatusCode hsc, Object o) throws IOException
  {
    String message = GSONUtil.DEFAULT_GSON.toJson(o);
    byte buffer[] = SharedStringUtil.getBytes(message);
    he.getResponseHeaders().add(HTTPHeaderName.CONTENT_TYPE.getName(), HTTPMimeType.APPLICATION_JSON.getValue());
    he.getResponseHeaders().add(HTTPHeaderName.CONTENT_TYPE.getName(), "charset=utf-8");
    he.sendResponseHeaders(hsc.CODE, buffer.length);
    he.getResponseBody().write(buffer);
  }

}
