package io.xlogistx.http.services;

import io.xlogistx.common.data.PropertyHolder;
import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.common.http.HTTPSessionHandler;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.util.*;

import java.io.IOException;
import java.io.InputStream;

public class HTTPUploadHandler
    extends PropertyHolder
    implements HTTPSessionHandler
{
    /**
     * @param hph
     * @throws IOException
     */
    @EndPointProp(methods = {HTTPMethod.POST, HTTPMethod.PUT}, name="upload-file", uris="/system-upload")
    @Override
    public void handle(@ParamProp(name="contents", source= Const.ParamSource.RESOURCE, optional=true)HTTPProtocolHandler hph)
            throws IOException
    {
        HTTPMessageConfigInterface hmciRequest = hph.getRequest();
        //System.out.println(hph.getRawRequest());
        System.out.println(hmciRequest.getParameters());


        for (GetNameValue<?> gnv : hmciRequest.getParameters().values())
        {
            if (gnv instanceof NamedValue)
            {
                if(gnv.getValue() instanceof InputStream)
                {
                    System.out.println(IOUtil.inputStreamToString((InputStream) gnv.getValue(), true));
                }
            }
            else if (gnv instanceof NVGenericMap)
            {
                System.out.println(gnv);
            }
            else
            {
                System.out.println(gnv);
            }
        }


        System.out.println("\n--------------------------------------------------\n" + hph.getRawRequest().getDataStream().toString());

        HTTPMessageConfigInterface hmciResponse = hph.buildResponse(HTTPStatusCode.OK,
                HTTPHeader.SERVER.toHTTPHeader((String) ResourceManager.SINGLETON.lookup(ResourceManager.Resource.HTTP_SERVER)));
        hmciResponse.setContentType(HTTPMediaType.APPLICATION_JSON);


//        HTTPUtil.formatResponse(hmci, protocolHandler.getResponseStream());
//        protocolHandler.getResponseStream().writeTo(protocolHandler.getOutputStream());
        HTTPUtil.formatResponse(hmciResponse, hph.getResponseStream())
                .writeTo(hph.getOutputStream());

    }

    /**
     *
     */
    @Override
    protected void refreshProperties() {

    }
}
