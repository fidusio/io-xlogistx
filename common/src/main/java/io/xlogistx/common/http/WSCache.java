package io.xlogistx.common.http;

import org.zoxweb.server.security.SecUtil;
import org.zoxweb.server.util.ReflectionUtil;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.http.HTTPWSProto;
import org.zoxweb.shared.util.BytesArray;
import org.zoxweb.shared.util.SharedUtil;

import javax.websocket.*;
import javax.websocket.server.ServerEndpoint;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.*;

public class WSCache {

    public static final String TEXT_STRING = "TEXT.String";
    public static final String TEXT_STRING_BOOLEAN = "TEXT.String.boolean";

    public static final String BINARY_BYTES_ARRAY = "BINARY.BytesArray";
    public static final String BINARY_BYTES_ARRAY_BOOLEAN = "BINARY.BytesArray.boolean";


    public enum WSMethodType {
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

        WSMethodType(HTTPWSProto.OpCode opCode, Class<? extends Annotation> aType, Class<?>... parameterTypes) {
            this.annotationType = aType;
            this.parameterTypes = parameterTypes;
            this.opCode = opCode;
        }

        public HTTPWSProto.OpCode getOpCode() {
            return opCode;
        }


        public Class<?>[] getParameterTypes() {
            return parameterTypes;
        }

        public Class<?> getMandatoryParameterType() {
            return parameterTypes.length > 0 ? parameterTypes[0] : null;
        }


//        public static Map<WSMethodType, Method> matchClassMethods(Class <?> c)
//        {
//            ReflectionUtil.AnnotationMap classAnnotationMap = ReflectionUtil.scanClassAnnotations(c,
//                    ServerEndpoint.class,
//                    OnMessage.class,
//                    OnOpen.class,
//                    OnClose.class,
//                    OnError.class,
//                    SecurityProp.class);
//            Map<WSMethodType, Method> ret = new HashMap<>();
//            for (WSMethodType wsmt : WSMethodType.values())
//            {
//                Method[] matching =  classAnnotationMap.matchingMethods(wsmt.annotationType);
//                if (matching != null && matching.length > 0)
//                {
//                    for(Method m : matching)
//                    {
//                        if (ReflectionUtil.doesMethodSupportParameters(false, m, wsmt.getMandatoryParameterType()))
//                        {
//                            // cache the security profile of the method;
//                            SecUtil.SINGLETON.applyAndCacheSecurityProfile(m, null);
//                            ret.put(wsmt, m);
//                            break;
//                        }
//                    }
//                }
//            }
//
//            return ret;
//        }

        public static Map<String, Method> matchClassMethodsByCanID(Class<?> c) {
            ReflectionUtil.AnnotationMap classAnnotationMap = ReflectionUtil.scanClassAnnotations(c,
                    ServerEndpoint.class,
                    OnMessage.class,
                    OnOpen.class,
                    OnClose.class,
                    OnError.class,
                    SecurityProp.class);
            Map<String, Method> ret = new HashMap<>();
            for (WSMethodType wsmt : WSMethodType.values()) {
                Method[] matching = classAnnotationMap.findMethodsByType(wsmt.annotationType);
                if (matching != null) {
                    for (Method m : matching) {

                        Set<Set<Class<?>>> combos = SharedUtil.combinationsAsSet(false, wsmt.getParameterTypes());

                        for (Set<Class<?>> classes : combos) {

                            if (ReflectionUtil.doesMethodSupportParameters(true, m, classes.toArray(new Class<?>[0]))) {
                                // cache the security profile of the method;
                                SecUtil.SINGLETON.applyAndCacheSecurityProfile(m, null);

//                            StringBuilder canID = new StringBuilder(wsmt.name());
//
//                            for(Class<?> clazz : m.getParameterTypes())
//                            {
//                                canID.append('.');
//                                canID.append(clazz.getSimpleName());
//                            }


                                ret.put(wsmt.toCanonicalID(m, wsmt.getParameterTypes()), m);
                                break;

                            }
                        }
                    }
                }
            }

            return ret;
        }

        public String toCanonicalID(Method m, Class<?>[] paramTypes) {
            StringBuilder canID = new StringBuilder(opCode != null ? opCode.name() : name());

            Class<?>[] tempo = new Class[1];
            for (Class<?> clazz : paramTypes) {
                tempo[0] = clazz;
                if (ReflectionUtil.doesMethodSupportParameters(false, m, tempo)) {
                    if (canID.length() > 0)
                        canID.append('.');
                    canID.append(clazz.getSimpleName());
                }
            }

            return canID.toString();

        }


    }


    private final Map<String, Method> map;


    public WSCache(Class<?> beanClass) {
        this(WSMethodType.matchClassMethodsByCanID(beanClass));
    }

    public WSCache(Map<String, Method> map) {
        this.map = map;
        mapData();


    }

//    private static <K,V> List<V> match(K key, Set<Map.Entry<K, V>> set, Matcher<K> matcher)
//    {
//        List<V> ret = new ArrayList<>();
//        for (Map.Entry<K,V> me: set)
//        {
//            if(matcher.match(me.getKey()))
//            {
//                ret.add(me.getValue());
//            }
//        }
//        return ret;
//    }


    private Map<String, Method> filter(String filter) {
        Map<String, Method> ret = new LinkedHashMap<>();
        Map.Entry<String, Method> match = null;

        for (Map.Entry<String, Method> kv : map.entrySet().toArray(new Map.Entry[0])) {
            if (kv.getKey().startsWith(filter)) {
                if (match == null) {
                    match = kv;
                } else if (kv.getValue().getParameterTypes().length > match.getValue().getParameterTypes().length) {
                    match = kv;
                }

                map.remove(kv.getKey());
            }
        }

        if (match != null) {
            ret.put(filter, match.getValue());
        }

        return ret;
    }

    private void mapData() {


        List<Map<String, Method>> toAdd = new ArrayList<>();
        // TEXT,

        toAdd.add(filter(TEXT_STRING_BOOLEAN));

        toAdd.add(filter(TEXT_STRING));

        // BIN,
        toAdd.add(filter(BINARY_BYTES_ARRAY_BOOLEAN));
        toAdd.add(filter(BINARY_BYTES_ARRAY));

        // PONG,
        Map<String, Method> pongMap = filter(WSMethodType.PONG.name());
        if (pongMap.size() > 1) {
            throw new IllegalArgumentException("More than one pong method");
        }
        toAdd.add(pongMap);
        // ERROR

        Map<String, Method> errorMap = filter(WSMethodType.ERROR.name());
        if (errorMap.size() > 1) {
            throw new IllegalArgumentException("More than one error method");
        }
        toAdd.add(errorMap);

        // OPEN
        Map<String, Method> openMap = filter(WSMethodType.OPEN.name());
        if (errorMap.size() > 1) {
            throw new IllegalArgumentException("More than one open method");
        }
        toAdd.add(openMap);


        // CLOSE

        Map<String, Method> closeMap = filter(WSMethodType.CLOSE.name());
        if (closeMap.size() > 1) {
            throw new IllegalArgumentException("More than one close method");
        }
        toAdd.add(closeMap);
        map.clear();
        for (Map<String, Method> add : toAdd) {
            add.entrySet().forEach(e -> map.put(e.getKey(), e.getValue()));
        }
    }


    public Map<String, Method> getCache() {
        return map;
    }


    public Method lookup(HTTPWSProto.OpCode opCode, boolean param) {
        Method ret = null;
        switch (opCode) {
            case TEXT:
                if (param)
                    ret = map.get(TEXT_STRING_BOOLEAN);
                else {
                    ret = map.get(TEXT_STRING);
                    if (ret == null) {
                        ret = map.get(TEXT_STRING_BOOLEAN);
                    }
                }
                break;
            case BINARY:
                if (param)
                    ret = map.get(BINARY_BYTES_ARRAY_BOOLEAN);
                else {
                    ret = map.get(BINARY_BYTES_ARRAY);
                    if (ret == null) {
                        ret = map.get(BINARY_BYTES_ARRAY_BOOLEAN);
                    }
                }
                break;
            case CLOSE:
                ret = map.get(opCode.name());
                break;
            case PONG:
                ret = map.get(opCode.name());
                break;

        }
        return ret;
    }

    public Method lookup(WSMethodType wsmt, boolean param) {
        Method ret = null;
        switch (wsmt) {
            case TEXT:
                ret = lookup(HTTPWSProto.OpCode.TEXT, param);
                break;
            case BINARY_BYTES:
                ret = lookup(HTTPWSProto.OpCode.BINARY, param);
                break;
            case BINARY_BYTE_BUFFER:
                break;
            case BINARY_BYTES_ARRAY:
                break;
            case PONG:
                ret = map.get(wsmt.name());
                break;
            case ERROR:
                ret = map.get(wsmt.name());
                break;
            case OPEN:
                ret = map.get(wsmt.name());
                break;
            case CLOSE:
                ret = map.get(wsmt.name());
                break;
        }
        return ret;
    }

}
