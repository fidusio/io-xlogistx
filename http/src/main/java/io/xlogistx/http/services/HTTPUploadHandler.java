package io.xlogistx.http.services;

import io.xlogistx.common.data.PropertyHolder;
import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.common.http.HTTPSessionHandler;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.http.HTTPHeader;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.ResourceManager;

import java.io.IOException;

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
        System.out.println(hmciRequest.getHeaders());

        HTTPMessageConfigInterface hmciResponse = hph.buildResponse(HTTPStatusCode.OK,
                HTTPHeader.SERVER.toHTTPHeader((String) ResourceManager.SINGLETON.lookup(ResourceManager.Resource.HTTP_SERVER)));


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
