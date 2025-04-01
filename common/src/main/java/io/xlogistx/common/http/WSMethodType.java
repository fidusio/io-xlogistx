package io.xlogistx.common.http;

import org.zoxweb.server.security.SecUtil;
import org.zoxweb.server.util.ReflectionUtil;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.protocol.HTTPWSProto;
import org.zoxweb.shared.util.BytesArray;

import javax.websocket.*;
import javax.websocket.server.ServerEndpoint;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

public enum WSMethodType
{




    TEXT(HTTPWSProto.OpCode.TEXT, OnMessage.class, String.class, boolean.class, Session.class),
    BINARY_BYTES(HTTPWSProto.OpCode.BINARY, OnMessage.class, byte[].class, boolean.class, Session.class),
    BINARY_BYTE_BUFFER(HTTPWSProto.OpCode.BINARY, OnMessage.class, ByteBuffer.class, boolean.class, Session.class),
    BINARY_BYTES_ARRAY(HTTPWSProto.OpCode.BINARY, OnMessage.class, BytesArray.class, boolean.class, Session.class),
    PONG(HTTPWSProto.OpCode.PONG, OnMessage.class, PongMessage.class, Session.class),
    ERROR(null, OnError.class, Throwable.class, Session.class),
    //OPEN(OnOpen.class),
    OPEN(null, OnOpen.class, Session.class),
    //CLOSE(OnClose.class),
    CLOSE(HTTPWSProto.OpCode.CLOSE, OnClose.class, Session.class, CloseReason.class),
    ;

    private final Class<? extends Annotation> annotationType;
    private final Class<?>[] parameterTypes;
    private final HTTPWSProto.OpCode opCode;
    WSMethodType(HTTPWSProto.OpCode opCode, Class<? extends Annotation> aType, Class<?> ...parameterTypes)
    {
        this.annotationType = aType;
        this.parameterTypes = parameterTypes;
        this.opCode = opCode;
    }

    public HTTPWSProto.OpCode getOpCode()
    {
        return opCode;
    }

    public Class<?> getMandatoryParameterType()
    {
        return parameterTypes.length > 0 ? parameterTypes[0] : null;
    }


    public static Map<WSMethodType, Method> matchClassMethods(Class <?> c)
    {
        ReflectionUtil.AnnotationMap classAnnotationMap = ReflectionUtil.scanClassAnnotations(c,
                ServerEndpoint.class,
                OnMessage.class,
                OnOpen.class,
                OnClose.class,
                OnError.class,
                SecurityProp.class);
        Map<WSMethodType, Method> ret = new HashMap<>();
        for (WSMethodType wsmt : WSMethodType.values())
        {
            Method[] matching =  classAnnotationMap.matchingMethods(wsmt.annotationType);
            if (matching != null && matching.length > 0)
            {
                for(Method m : matching)
                {
                    if (ReflectionUtil.doesMethodSupportParameters(false, m, wsmt.getMandatoryParameterType()))
                    {
                        // cache the security profile of the method;
                        SecUtil.SINGLETON.applyAndCacheSecurityProfile(m, null);
                        ret.put(wsmt, m);
                        break;
                    }
                }
            }
        }

        return ret;
    }

}