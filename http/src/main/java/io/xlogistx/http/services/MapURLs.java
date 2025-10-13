package io.xlogistx.http.services;

import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.NVGenericMap;

public class MapURLs {

    public static final LogWrapper log = new LogWrapper(MapURLs.class).setEnabled(true);

    @EndPointProp(methods = {HTTPMethod.POST}, name = "map", uris = "/map/url")
    @SecurityProp(authentications = {CryptoConst.AuthenticationType.ALL}, permissions = "system:add:mapped:url")
    public NVGenericMap mapURL(@ParamProp(name = "mapped-name", source = Const.ParamSource.PAYLOAD) NVGenericMap mapProp)
    {
        if(log.isEnabled()) log.getLogger().info("" + mapProp);


        NVGenericMap ret = new NVGenericMap();

        return ret;
    }
}
