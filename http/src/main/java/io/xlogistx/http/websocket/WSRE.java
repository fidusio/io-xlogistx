package io.xlogistx.http.websocket;

import io.xlogistx.common.http.HTTPProtocolHandler;
import org.apache.shiro.subject.Subject;

public class WSRE {
    public final WSRemoteEndPoint.WSBasic basic;
    public final WSRemoteEndPoint.WSAsync async;

    private WSRE(WSRemoteEndPoint.WSBasic basic, WSRemoteEndPoint.WSAsync async)
    {
        this.basic = basic;
        this.async = async;

    }


    public static WSRE create(HTTPProtocolHandler<Subject> hph)
    {
        return new WSRE(new WSRemoteEndPoint.WSBasic(hph), new WSRemoteEndPoint.WSAsync(hph));
    }
}
