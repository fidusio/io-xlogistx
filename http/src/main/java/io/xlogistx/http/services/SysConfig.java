package io.xlogistx.http.services;

import io.xlogistx.common.data.PropertyHolder;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.data.SimpleMessage;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.security.model.SecurityModel;
import org.zoxweb.shared.util.NVBoolean;

public class SysConfig
        extends PropertyHolder
{

    @EndPointProp(methods = {HTTPMethod.GET}, name="gson-enum-format", uris="/gson/simple/format/{format}")
    @SecurityProp(authentications = {CryptoConst.AuthenticationType.ALL}, permissions = "gson:" + SecurityModel.PERM_ACCESS)
    public SimpleMessage gsonEnumFormat(@ParamProp(name = "format") boolean format)
    {
        GSONUtil.SIMPLE_FORMAT = format;
        SimpleMessage ret = new SimpleMessage("SGON enum format", HTTPStatusCode.OK.CODE);
        ret.getProperties().build(new NVBoolean("simple_format", GSONUtil.SIMPLE_FORMAT));
        return ret;
    }
    @Override
    protected void refreshProperties()
    {

    }
}
