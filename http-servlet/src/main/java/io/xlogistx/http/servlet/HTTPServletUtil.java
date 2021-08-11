/*
 * Copyright (c) 2012-2017 ZoxWeb.com LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package io.xlogistx.http.servlet;

import io.xlogistx.common.data.MethodHolder;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.zoxweb.server.http.HTTPRequestAttributes;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.io.FileInfoStreamSource;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.server.util.GSONWrapper;
import org.zoxweb.server.util.ZIPUtil;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.api.APIError;
import org.zoxweb.shared.data.FileInfoDAO;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.util.*;
import org.zoxweb.shared.util.SharedBase64.Base64Type;

import javax.servlet.Servlet;
import javax.servlet.ServletContext;
import javax.servlet.ServletRegistration;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Parameter;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.*;
import java.util.logging.Logger;


public class HTTPServletUtil
{
	public static final int ZIP_LIMIT = 1024;
	public static GSONWrapper GSON_WRAPPER = new GSONWrapper(Base64Type.DEFAULT);
	public static boolean ACAO = true;
	
	private static final transient Logger log = Logger.getLogger(HTTPServletUtil.class.getName());

	private HTTPServletUtil()
	{
		
	}

	
	public static List<GetNameValue<String>> extractRequestHeaders(HttpServletRequest req)
	{
		ArrayList<GetNameValue<String>> ret = new ArrayList<GetNameValue<String>>();
		
		
		Enumeration<String> headerNames = req.getHeaderNames();
		for (; headerNames.hasMoreElements();)
		{
			String headerName = headerNames.nextElement();
			Enumeration<String> headerValues = req.getHeaders(headerName);
			for (; headerValues.hasMoreElements();)
			{
				ret.add(new NVPair(headerName, headerValues.nextElement()));
			}
		}
		
		
		
		return ret;
	}
	
	
	public static HTTPRequestAttributes extractRequestAttributes(HttpServletRequest req) throws IOException
	{
		return extractRequestAttributes(req, true);
	}
	
	@SuppressWarnings("unchecked")
	public static HTTPRequestAttributes extractRequestAttributes(HttpServletRequest req, boolean readParameters) throws IOException
	{
		HTTPRequestAttributes ret = null;
		
		DiskFileItemFactory dfif = null;
		List<FileItem> items = null;
		// check if the request is of multipart type
		List<GetNameValue<String>> headers = extractRequestHeaders(req);
		List<GetNameValue<String>> params = new ArrayList<GetNameValue<String>>();
		List<FileInfoStreamSource> streamList = new ArrayList<FileInfoStreamSource>();
		
		/*
		 * 	Retrieve path info if it exists. If the pathInfo starts or ends with a "/", the "/" is removed
		 * 	and value is trimmed.
		 */
		String pathInfo = req.getPathInfo();
		//	Removing the first "/" in pathInfo.
		pathInfo = SharedStringUtil.trimOrNull(SharedStringUtil.valueAfterLeftToken(pathInfo, "/"));
		//	Removing the last "/" in pathInfo.
		if (pathInfo != null)
		{
			if (pathInfo.endsWith("/"))
			{
				pathInfo = SharedStringUtil.trimOrNull(pathInfo.substring(0, pathInfo.length() - 1));
			}
		}
		
		if (ServletFileUpload.isMultipartContent(req))
		{
			
			dfif = new DiskFileItemFactory();
			try
			{
				ServletFileUpload upload = new ServletFileUpload(dfif);
				upload.setHeaderEncoding(SharedStringUtil.UTF_8);
				items = upload.parseRequest(req);
			}
			catch ( FileUploadException e )
			{
				throw new IOException("Upload problem:" + e);
			}
			for ( FileItem fi : items)
			{
				if ( fi.isFormField())
				{
					String name = fi.getFieldName();
					String value = fi.getString();
					params.add( new NVPair(name, value));
				
				}
				else
				{
					String content = fi.getContentType();
					InputStream is = fi.getInputStream();
					String filename = fi.getName();
					FileInfoDAO fid = new FileInfoDAO();
					fid.setName(filename);
					fid.setCreationTime(System.currentTimeMillis());
					fid.setContentType(content);
					fid.setLength(fi.getSize());
					

					
					
					FileInfoStreamSource fiss = new FileInfoStreamSource( fid, is);
					streamList.add( fiss);
				}
			}
			
			ret = new HTTPRequestAttributes(req.getRequestURI(), pathInfo, req.getContentType(), true, headers, params, streamList);
		}
		else
		{
			if (readParameters)
			{
				params = (List<GetNameValue<String>>) SharedUtil.toNVPairs(req.getParameterMap());
			}
			 
			 
			ret = new HTTPRequestAttributes(req.getRequestURI(), pathInfo, req.getContentType(), false, headers, params, streamList, new HTTPRequestStringContentDecoder(req));
		}
		
		return ret; 
	}
	
	
	public static String toString(HttpServletRequest req) throws IOException
	{
		StringBuilder sb = new StringBuilder();
		List<GetNameValue<String>> headers    = HTTPServletUtil.extractRequestHeaders(req);
		@SuppressWarnings("unchecked")
		List< GetNameValue<String>> parameters = (List<GetNameValue<String>>) SharedUtil.toNVPairs(req.getParameterMap());
		String method = req.getMethod();
		sb.append( "Method:" + method + "\n");
		sb.append( "Headers:\n");
		sb.append( headers);
		sb.append( "Parameters:\n");
		if (parameters == null || parameters.size() == 0)
		{
			UByteArrayOutputStream baos = IOUtil.inputStreamToByteArray(req.getInputStream(), false);
			sb.append("binary data:" + baos.size() + "\n");
			sb.append(new String(SharedBase64.encode( baos.toByteArray())));
		}
		else
			sb.append( parameters);
		return sb.toString();
	}
	
	
	
	
	
	
	

	
	
	public static HTTPHeaderValue shouldZIPResponseContent(HttpServletRequest request, String responseContent)
	{
		if (exceedsUncompressedContentLengthLimit(responseContent))
		{
			return acceptsZIPEncoding(request);
		}
		
		return null;
	}

	public static void setZIPEncodingHeader(HttpServletResponse response, HTTPHeaderValue hv)
	{
		if (hv != null)
			response.setHeader(HTTPHeaderName.CONTENT_ENCODING.getName(), hv.getValue());
	}
	
	public static boolean exceedsUncompressedContentLengthLimit(String content)
	{
		return content.length() > ZIP_LIMIT;
	}
	
	public static HTTPHeaderValue acceptsZIPEncoding(HttpServletRequest req)
	{
		HTTPHeaderValue zip = null;
		if (req != null)
		{
			String encoding = req.getHeader(HTTPHeaderName.X_ACCEPT_ENCODING.getName());
			if (encoding == null)
			{
				encoding = req.getHeader(HTTPHeaderName.ACCEPT_ENCODING.getName());
			}
			
			if (SharedStringUtil.contains(encoding, HTTPHeaderValue.CONTENT_ENCODING_LZ, true))
			{
				zip = HTTPHeaderValue.CONTENT_ENCODING_LZ;
			}
			else if (SharedStringUtil.contains(encoding, HTTPHeaderValue.CONTENT_ENCODING_GZIP, true))
			{
				zip = HTTPHeaderValue.CONTENT_ENCODING_GZIP;
				//zip = HTTPHeaderValue.CONTENT_ENCODING_LZ;
			}
		}
		
		return zip;
	  }
	
	
	
	public static byte[] compress(String zipMode, byte[] content) throws NullPointerException, IllegalArgumentException, IOException
	{
		SharedUtil.checkIfNulls("null value", zipMode, content);
		zipMode = zipMode.toLowerCase();
		switch(zipMode)
		{
		
		case "gzip":
			
			
			return ZIPUtil.gzip(content);
			
//			ByteArrayOutputStream output = null;
//			GZIPOutputStream gzipOutputStream = null;
//			try
//			{
//				output = new ByteArrayOutputStream(content.length);
//				gzipOutputStream = new GZIPOutputStream(output);
//				gzipOutputStream.write(content);
//				gzipOutputStream.flush();
//				gzipOutputStream.finish();
//				return output.toByteArray();
//			}
//			catch(IOException e)
//			{
//			  throw new IllegalArgumentException(e.getMessage());
//			}
//			finally
//			{
//				ServerUtil.close(gzipOutputStream);
//			}
		      
			
		case "lz":
			return  QuickLZ.compress(content, 1);
		
		default:
			throw new IllegalArgumentException("unsupported compression mode " + zipMode);
		
		}
	}
	
	
	
	public static <V> int sendJSONObj(HttpServletRequest req, HttpServletResponse resp, HTTPStatusCode code, V obj)
        throws IOException
    {
    	if(obj instanceof NVGenericMap)
      	{
			return sendJSON( req,  resp,  code, false, GSONUtil.toJSONGenericMap((NVGenericMap) obj, false, false, false));
		}
	  if( obj instanceof NVEntity)
	  {
		return sendJSON( req,  resp,  code, (NVEntity) obj);
	  }


	  return sendJSON( req,  resp,  code, false, GSONUtil.DEFAULT_GSON.toJson(obj));
    }
	
	
	public static int sendJSON(HttpServletRequest req, HttpServletResponse resp, HTTPStatusCode code, NVEntity nve)
			throws IOException
	{
		String json = null;
		if (nve != null)
		{
			json = nve instanceof APIError ? GSON_WRAPPER.toJSON(nve, true, false, true) : GSON_WRAPPER.toJSON(nve, false, false, true);
		}
		
		return sendJSON(req, resp, code, json);
	}
	
	public static int sendJSON(HttpServletRequest req, HttpServletResponse resp, HTTPStatusCode code, List<? extends NVEntity> nves)
			throws IOException
	{	
		return sendJSON(req, resp, code, nves != null ? GSON_WRAPPER.toJSONValues(nves.toArray(new NVEntity[0]), false, false, true) : null);	
	}
	
	public static int sendJSON(HttpServletRequest req, HttpServletResponse resp, HTTPStatusCode code, NVEntity nves[])
			throws IOException
	{	
		return sendJSON(req, resp, code, nves != null ? GSON_WRAPPER.toJSONValues(nves, false, false, true) : null);
	}
	
	
	public static int sendJSON(HttpServletRequest req, HttpServletResponse resp, HTTPStatusCode code, String json)
        throws IOException
    {
	  return sendJSON(req, resp, code, true, json);
    }
	
	
	public static int sendJSON(HttpServletRequest req, HttpServletResponse resp, HTTPStatusCode code, boolean zipMaybe, String json)
			throws IOException
	{
		resp.setStatus(code.CODE);
		resp.setContentType(HTTPMimeType.APPLICATION_JSON.getValue());
		resp.setCharacterEncoding(SharedStringUtil.UTF_8);
		resp.setHeader("Cache-Control", "no-cache, no-store, must-revalidate"); // HTTP 1.1.
		resp.setHeader("Pragma", "no-cache"); // HTTP 1.0.
		//resp.setHeader("Access-Control-Allow-Origin", "*");
		resp.setDateHeader("Expires", 0); // Proxies.
		// allow cross site access
		if (ACAO)
		  resp.addHeader("Access-Control-Allow-Origin", "*");
		
		if (json != null)
		{
		  
		  
		    if (zipMaybe)
		    {
    			HTTPHeaderValue zip = shouldZIPResponseContent(req, json);
    			
    			if (zip != null)
    			{
    				setZIPEncodingHeader(resp, zip);
    				byte toZip [] = SharedStringUtil.getBytes(json);
    				log.info("content will be compressed " + zip + " size " + toZip.length );
    				// compress
    				byte[] responseBytes = compress(zip.getValue(), toZip);
    				// encode base64
    				if (zip == HTTPHeaderValue.CONTENT_ENCODING_LZ)
    				{
    					responseBytes = SharedBase64.encode(responseBytes);
    				}
    				else if (zip == HTTPHeaderValue.CONTENT_ENCODING_GZIP)
    				{
    					resp.setHeader(HTTPHeaderName.CONTENT_DISPOSITION.getName(), "attachment");
    				}
    				resp.getOutputStream().write(responseBytes);
    				return responseBytes.length;	
    			}
		    }
			
			byte[] toWrite = SharedStringUtil.getBytes(json);
			
			resp.getOutputStream().write(toWrite);	
			return toWrite.length;
		}
		
		return 0;
	}
	
	public static String inputStreamToString(ServletContext context, String resource) throws NullPointerException, IOException
	{
		log.info("resource:" + resource);
		String content = null;
		try
		{
			content = (IOUtil.inputStreamToString(context.getClass().getResourceAsStream(resource), true));
		}
		catch(Exception e)
		{
			
		}
		if (content == null)
		{

			URL url = context.getResource(resource);
			log.info("url:" + url);
			//content = inputStreamToString(context, resource);
			content = (IOUtil.inputStreamToString(context.getResourceAsStream(resource), true));
		}
		
		
		return content;
	}


//	public static String inputStreamToString(ServletContext context, String resource) throws NullPointerException, IOException
//	{
//		log.info("resource:" + resource);
//		URL url = context.getResource(resource);
//		log.info("url:" + url);
//		return (IOUtil.inputStreamToString(context.getResourceAsStream(resource), true));
//	}


	public static String inputStreamToString(Class<?> clazz, String resource) throws NullPointerException, IOException
	{
		log.info("resource:" + resource);
		String content = null;
		try
		{
			content = (IOUtil.inputStreamToString(clazz.getResourceAsStream(resource), true));
		}
		catch(Exception e)
		{

		}

		return content;
	}



	public static HTTPEndPoint servletToEndPoint(Class<?> clazz)
	{
		HTTPEndPoint hep = new HTTPEndPoint();
		for (Annotation a : clazz.getAnnotations())
		{

			if (a.annotationType() == WebServlet.class)
			{
				WebServlet ws = (WebServlet) a;
				hep.setName(ws.name());
				hep.setPaths(ws.urlPatterns());
				hep.setBean(clazz.getName());
			}
		}

		return hep;
	}

	public static ServletRegistration.Dynamic dynamicRegistration(ServletContext sc, String name, Class <? extends Servlet>  servletClass, String ... urlPatterns)
	{
		HTTPEndPoint hep = servletToEndPoint(servletClass);

		if (SharedStringUtil.isEmpty(name))
			name = hep.getName();
		if(urlPatterns == null || urlPatterns.length == 0)
			urlPatterns = hep.getPaths();

		ServletRegistration.Dynamic registration = sc.addServlet(name, servletClass);
		registration.addMapping(urlPatterns);
		return registration;
	}

	public static void dynamicRegistration(ServletContext sc, HTTPServerConfig endPoints)
	{
		log.info("" + endPoints);
		for (HTTPEndPoint hep : endPoints.getEndPoints())
		{
			dynamicRegistration(sc, hep);
		}
	}


	public static void dynamicRegistration(ServletContext sc, HTTPEndPoint hep)
	{
		try
		{

			Class<?> c = Class.forName(hep.getBean());
			if (HttpServlet.class.isAssignableFrom(c)) {
				HTTPEndPoint servletHep = servletToEndPoint(c);
				if (hep.getName().equals(hep.getBean())) hep.setName(servletHep.getName());
				if (SharedUtil.isEmpty(hep.getPaths())) hep.setPaths(servletHep.getPaths());

				ServletRegistration.Dynamic registration = sc.addServlet(hep.getName(), (Class<? extends Servlet>) c);
				registration.addMapping(hep.getPaths());
				log.info("Created: " + hep.getName() + ":" + hep);
			}
		}
		catch (Exception e)
		{
			e.printStackTrace();
			log.info("Error loading: " + hep);
		}

	}


//	public static Map<String, Object>  buildParameters(HttpServletRequest req, HTTPEndPoint hep, MethodHolder mh) throws URISyntaxException {
//    	String hePath = req.getServletPath();
//
//
//
//		URI uri = new URI(req.getRequestURI());
//
//		// parse the path parameters
//		Map<String, Object> parameters = HTTPUtil.parsePathParameters(hep.getPaths()[0], uri.getPath(), false);
//
//		// parse the query parameters if they are set in the body
//		if (!SharedStringUtil.isEmpty(uri.getQuery()))
//		{
//			List<GetNameValue<String>> queryParameters = HTTPUtil.parseQuery(uri.getQuery());
//
//			if(queryParameters != null && queryParameters.size() > 0)
//			{
//				for(GetNameValue<String> gnv : queryParameters)
//					parameters.put(gnv.getName(), gnv.getValue());
//
//			}
//		}
//
//		List<String> contentTypeData = he.getRequestHeaders().get(HTTPHeaderName.CONTENT_TYPE.getName());
//		HTTPMimeType contentType = contentTypeData != null && contentTypeData.size() > 0 ? HTTPMimeType.lookup(contentTypeData.get(0)) : null;
//
//		String  payload = null;
//		// parse if not post for n=v&n2=v2 body
//		if (!he.getRequestMethod().equalsIgnoreCase(HTTPMethod.GET.getName()) && contentType == HTTPMimeType.APPLICATION_WWW_URL_ENC)
//		{
//			payload = IOUtil.inputStreamToString(he.getRequestBody(), true);
//			List<GetNameValue<String>> payloadParameters = HTTPUtil.parseQuery(payload);
//
//			if(payloadParameters != null && payloadParameters.size() > 0)
//			{
//				for(GetNameValue<String> gnv : payloadParameters)
//					parameters.put(gnv.getName(), gnv.getValue());
//			}
//		}
//		else if (contentType == HTTPMimeType.APPLICATION_JSON)
//		{
//			payload = IOUtil.inputStreamToString(he.getRequestBody(), true);
//		}
//		//log.info("payload:" + payload);
//
//
//		// need to parse the payload parameters
//		for(Parameter p : eph.getMethodHolder().getMethodAnnotations().method.getParameters())
//		{
//			Annotation pAnnotation  = eph.getMethodHolder().getMethodAnnotations().parametersAnnotations.get(p);
//			if(pAnnotation != null  && pAnnotation instanceof ParamProp)
//			{
//				ParamProp pp = (ParamProp) pAnnotation;
//				if (pp.source() == Const.ParamSource.PAYLOAD)
//				{
//					Class<?> pClassType = p.getType();
//					if (contentType != null)
//					{
//
//						switch (contentType)
//						{
//
//							case APPLICATION_WWW_URL_ENC:
//								// this case is impossible to happen
//								break;
//							case APPLICATION_JSON:
//
//								Object v = GSONUtil.DEFAULT_GSON.fromJson(payload, pClassType);
//								parameters.put(pp.name(), v);
//
//
//								break;
//							case APPLICATION_OCTET_STREAM:
//								break;
//							case MULTIPART_FORM_DATA:
//								break;
//							case TEXT_CSV:
//								break;
//							case TEXT_CSS:
//								break;
//							case TEXT_HTML:
//								break;
//							case TEXT_JAVASCRIPT:
//								break;
//							case TEXT_PLAIN:
//								break;
//							case TEXT_YAML:
//								break;
//							case IMAGE_BMP:
//								break;
//							case IMAGE_GIF:
//								break;
//							case IMAGE_JPEG:
//								break;
//							case IMAGE_PNG:
//								break;
//							case IMAGE_SVG:
//								break;
//							case IMAGE_ICON:
//								break;
//							case IMAGE_TIF:
//								break;
//						}
//
//					}
//
//					// read the payload and convert string to class
//				}
//
//				// check if null and optional
//				Object currentValue = parameters.get(pp.name());
//
//				if (currentValue == null) {
//					if (pp.optional()) {
//						if (SharedUtil.isPrimitive(p.getType())) {
//							NVBase<?> paramValue = SharedUtil.classToNVBase(p.getType(), pp.name(), null);
//							parameters.put(pp.name(), paramValue != null ? paramValue.getValue() : null);
//						}
//						continue;
//					}
//					else
//						throw new IllegalArgumentException("Missing parameter " + pp.name());
//				}
//
//				if(SharedUtil.isPrimitive(p.getType()) || Enum.class.isAssignableFrom(p.getType()) || Enum[].class.isAssignableFrom(p.getType()))
//				{
//					parameters.put(pp.name(), SharedUtil.classToNVBase(p.getType(), pp.name(), (String)currentValue).getValue());
//				}
//			}
//		}
//
//		return parameters;
//	}
}