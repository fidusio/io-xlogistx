package io.xlogistx.http.handler;

import com.sun.net.httpserver.HttpExchange;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.server.util.ReflectionUtil;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.data.SimpleMessage;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.util.*;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationTargetException;

import java.lang.reflect.Parameter;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;

@SuppressWarnings("restriction")
public class HTTPHandlerUtil {

  private static transient Logger log = Logger.getLogger(HTTPHandlerUtil.class.getName());

  private HTTPHandlerUtil()
  {
    
  }

  public static void sendErrorMessage(HttpExchange he, HTTPStatusCode hsc, String msg) throws IOException
  {
    sendErrorMessage(he, hsc, msg, false);
  }

  public static void sendErrorMessage(HttpExchange he, HTTPStatusCode hsc, String msg, boolean close) throws IOException
  {
    SimpleMessage sem = new SimpleMessage(msg, hsc.CODE, hsc.REASON);
    sem.setCreationTime(System.currentTimeMillis());
    sendSimpleMessage(he, hsc, sem, close);
  }


  public static void sendSimpleMessage(HttpExchange he, HTTPStatusCode hsc, String simpleMessage) throws IOException
  {
    sendSimpleMessage(he, hsc, new SimpleMessage(simpleMessage, hsc.CODE));
  }


  public static void sendSimpleMessage(HttpExchange he, HTTPStatusCode hsc, SimpleMessage simpleMessage) throws IOException
  {
    sendSimpleMessage(he, hsc, simpleMessage, false);
  }
  public static void sendSimpleMessage(HttpExchange he, HTTPStatusCode hsc, SimpleMessage simpleMessage, boolean close) throws IOException
  {
    String message = GSONUtil.toJSON(simpleMessage, false, false, false);
    byte buffer[] = SharedStringUtil.getBytes(message);
    he.getResponseHeaders().add(HTTPHeaderName.CONTENT_TYPE.getName(), HTTPMimeType.APPLICATION_JSON.getValue());
    he.getResponseHeaders().add(HTTPHeaderName.CONTENT_TYPE.getName(), "charset=utf-8");
    he.sendResponseHeaders(hsc.CODE, buffer.length);
    log.info("buffer:" + buffer + " " + message);
    he.getResponseBody().write(buffer);
    if(close)
      he.close();
  }


  public static void sendJSONResponse(HttpExchange he, HTTPStatusCode hsc, Object o) throws IOException
  {
    sendJSONResponse(he, hsc, o, false);
  }


  public static void sendJSONResponse(HttpExchange he, HTTPStatusCode hsc, Object o, boolean close) throws IOException
  {
    String message = GSONUtil.DEFAULT_GSON.toJson(o);
    byte buffer[] = SharedStringUtil.getBytes(message);
    he.getResponseHeaders().add(HTTPHeaderName.CONTENT_TYPE.getName(), HTTPMimeType.APPLICATION_JSON.getValue());
    he.getResponseHeaders().add(HTTPHeaderName.CONTENT_TYPE.getName(), "charset=utf-8");
    he.sendResponseHeaders(hsc.CODE, buffer.length);
    he.getResponseBody().write(buffer);
    if(close)
      he.close();
  }


  public static NVGenericMap buildParameters(HttpExchange he, HTTPEndPoint hep, ReflectionUtil.MethodAnnotations ma) throws IOException {

    String hePath = he.getHttpContext().getPath();
    URI uri = he.getRequestURI();
//    log.info("uri:" + uri);
//    log.info("query:" + uri.getQuery());
//    log.info("raw query:" + uri.getRawQuery());
//    log.info("uri path:" + uri.getPath());
//    log.info("context path:" + hePath);
    // parse the path parameters
    NVGenericMap ret = HTTPUtil.parsePathParameters(hep.getPaths()[0], uri.getPath(), false);
//    log.info("ret step 1:" + ret);

    // parse the query parameters if they are set in the body
    if (!SharedStringUtil.isEmpty(uri.getQuery()))
    {
      List<GetNameValue<String>> queryParameters = HTTPUtil.parseQuery(uri.getQuery());
      if(queryParameters != null && queryParameters.size() > 0)
      {
        for(GetNameValue<String> gnvs : queryParameters)
          ret.add(gnvs);
      }
    }

    LinkedList<String> contentTypeData = (LinkedList<String>)he.getRequestHeaders().get(HTTPHeaderName.CONTENT_TYPE.getName());
    HTTPMimeType contentType = contentTypeData != null && contentTypeData.size() > 0 ? HTTPMimeType.lookup(contentTypeData.get(0)) : null;

    String  payload = null;
    // parse if not post for n=v&n2=v2 body
    if (!he.getRequestMethod().equalsIgnoreCase(HTTPMethod.GET.getName()) && contentType == HTTPMimeType.APPLICATION_WWW_URL_ENC)
    {
      payload = IOUtil.inputStreamToString(he.getRequestBody(), true);
      List<GetNameValue<String>> payloadParameters = HTTPUtil.parseQuery(payload);

      if(payloadParameters != null && payloadParameters.size() > 0)
      {
        for(GetNameValue<String> gnvs : payloadParameters)
          ret.add(gnvs);
      }
    }
    else if (contentType == HTTPMimeType.APPLICATION_JSON)
    {
      payload = IOUtil.inputStreamToString(he.getRequestBody(), true);
    }
    log.info("payload:" + payload);


    // need to parse the payload parameters
    for(Parameter p : ma.method.getParameters())
    {
      Annotation pAnnotation  = ma.parametersAnnotations.get(p);
      if(pAnnotation != null  && pAnnotation instanceof ParamProp)
      {
        ParamProp pp = (ParamProp) pAnnotation;
        log.info("" + pp);

        if (pp.paramSource() == Const.ParamSource.PAYLOAD)
        {
          Class<?> pClassType = p.getType();
          if (contentType != null)
          {

              switch (contentType)
              {

                case APPLICATION_WWW_URL_ENC:
                  // this case is impossible to happen
                  break;
                case APPLICATION_JSON:

                  Object v = GSONUtil.DEFAULT_GSON.fromJson(payload, pClassType);
                  if(v instanceof NVGenericMap) {
                    NVGenericMap vNVGP = (NVGenericMap) v;
                    vNVGP.setName(pp.name());
                    ret.add(vNVGP);
                  }
                  if(v instanceof NVEntity)
                  {
                    log.info("" + v);
                    ret.add(pp.name(), (NVEntity) v);
                  }

                  break;
                case APPLICATION_OCTET_STREAM:
                  break;
                case MULTIPART_FORM_DATA:
                  break;
                case TEXT_CSV:
                  break;
                case TEXT_CSS:
                  break;
                case TEXT_HTML:
                  break;
                case TEXT_JAVASCRIPT:
                  break;
                case TEXT_PLAIN:
                  break;
                case TEXT_YAML:
                  break;
                case IMAGE_BMP:
                  break;
                case IMAGE_GIF:
                  break;
                case IMAGE_JPEG:
                  break;
                case IMAGE_PNG:
                  break;
                case IMAGE_SVG:
                  break;
                case IMAGE_ICON:
                  break;
                case IMAGE_TIF:
                  break;
              }

          }

          // read the payload and convert string to class
        }
        GetNameValue<?> currentGNV = ret.get(pp.name());
        GetNameValue<?> expectedGNV = null;
        if(currentGNV!=null && currentGNV.getValue() instanceof String)
          expectedGNV = SharedUtil.classToNVBase(p.getType(), pp.name(),  (String)currentGNV.getValue());
        if (currentGNV == null)
        {
          if(pp.optional())
            ret.add(expectedGNV);
          else
            throw new IllegalArgumentException("Missing parameter " + pp.name());
        }
        else if(expectedGNV != null && currentGNV.getClass() != expectedGNV.getClass())
        {
          // try to convert the string value
          ret.add(expectedGNV);
        }


      }
    }

    return ret;
  }




  public static Object invokeMethod(Object source, ReflectionUtil.MethodAnnotations methodAnnotations, NVGenericMap incomingData)
          throws InvocationTargetException, IllegalAccessException
  {
    Object result = null;
    List<Object> parameterValues = new ArrayList<Object>();
    Parameter[] parameters = methodAnnotations.method.getParameters();
    Object[] values = new Object[parameters.length];

    for(int i =0; i < values.length; i++)
    {
      ParamProp pp = (ParamProp) methodAnnotations.parametersAnnotations.get(parameters[i]);
      values[i] = incomingData.get(pp.name()).getValue();
    }


    log.info("" +  methodAnnotations.method + " " + Arrays.toString(values));
    result = methodAnnotations.method.invoke(source, values);

    return result;
  }

  public static boolean isMethodParameterAnnotated(ReflectionUtil.MethodAnnotations ma, Class<? extends Annotation> aClass)
  {

    if(ma != null)
    {
      for(Parameter p : ma.method.getParameters())
      {
        Annotation paAnnotations = ma.parametersAnnotations.get(p);
        if(paAnnotations == null || paAnnotations.annotationType() != aClass)
        {
          return false;
        }
      }
    }
    else
    {
      return false;
    }

    return true;
  }
}
