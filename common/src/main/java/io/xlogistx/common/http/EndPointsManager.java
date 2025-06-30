package io.xlogistx.common.http;


import io.xlogistx.common.data.MethodHolder;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.SecUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.server.util.ReflectionUtil;
import org.zoxweb.shared.annotation.*;
import org.zoxweb.shared.http.HTTPEndPoint;
import org.zoxweb.shared.http.HTTPMediaType;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;
import org.zoxweb.shared.http.HTTPServerConfig;
import org.zoxweb.shared.util.*;

import javax.websocket.OnClose;
import javax.websocket.OnError;
import javax.websocket.OnMessage;
import javax.websocket.OnOpen;
import javax.websocket.server.ServerEndpoint;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.*;

public class EndPointsManager {

    public final static LogWrapper log = new LogWrapper(EndPointsManager.class).setEnabled(false);

    private final URIMap<EndPointMeta> uriEndPointMeta = new URIMap<>();
    private final Map<String, Object> beanMaps = new LinkedHashMap<>();
    private final InstanceFactory.ParamsInstanceCreator<?> pic;
    private MethodHolder onStartup, onShutdown;

    private EndPointsManager(InstanceFactory.ParamsInstanceCreator<?> pic) {
        this.pic = pic;
    }

    public synchronized EndPointMeta map(String uri, HTTPEndPoint hep, MethodHolder mh) {
        uri = SharedStringUtil.toTrimmedLowerCase(uri);
        SUS.checkIfNulls("Mapping parameters can't be null", uri, hep);
        EndPointMeta epm = new EndPointMeta(hep, mh);
        uriEndPointMeta.put(uri, epm);
        return epm;
    }

    private void mapBean(Object bean, Object mappedProp) {
        if (mappedProp != null) {
            log.getLogger().info("MappedProp found: " + mappedProp);
            if (mappedProp instanceof MappedProp) {
                beanMaps.put(((MappedProp) mappedProp).name(), bean);
                if (SUS.isNotEmpty(((MappedProp) mappedProp).id()))
                    beanMaps.put(((MappedProp) mappedProp).id(), bean);
            }
            if (mappedProp instanceof ServerEndpoint) {
                beanMaps.put("ws-" + ((ServerEndpoint) mappedProp).value(), bean);
            }
        }

        log.getLogger().info("class name " + bean.getClass().getName());
        beanMaps.put(bean.getClass().getName(), bean);
    }

    public synchronized <B> B lookupBean(String beanID) {
        return (B) beanMaps.get(beanID);
    }


    public EndPointMeta unmap(String uri) {
        return uriEndPointMeta.remove(uri);
    }

    public EndPointMeta lookup(String uri) {
        return uriEndPointMeta.lookup(uri);
    }

    public URIMap.URIMapResult<EndPointMeta> lookupWithPath(String uri) {
        return uriEndPointMeta.lookupWithPath(uri);
    }

    public static HTTPEndPoint updatePaths(String baseURI, HTTPEndPoint hep) {
        baseURI = SharedStringUtil.trimOrNull(baseURI);
        if (baseURI != null) {
            String[] paths = hep.getPaths();
            for (int i = 0; i < paths.length; i++) {
                paths[i] = updatePath(baseURI, paths[i]);
            }
            hep.setPaths(paths);
        }
        return hep;
    }

    public static String updatePath(String baseURI, String path) {
        baseURI = SharedStringUtil.trimOrNull(baseURI);
        if (baseURI != null) {
            path = SharedStringUtil.concat(baseURI, path, "/");
        }
        return path;
    }


    public static HTTPEndPoint applyAnnotations(String baseURI, HTTPEndPoint hep, Annotation[] annotations, boolean methodCheck) {
        for (Annotation a : annotations) {
            if (a instanceof EndPointProp) {
                EndPointProp epp = (EndPointProp) a;
                hep.setName(epp.name());
                hep.setDescription(epp.description());
                hep.setHTTPMethods(epp.methods());
                hep.setInputContentType(epp.requestContentType());
                hep.setOutputContentType(epp.responseContentType());

                String[] uris = SharedStringUtil.parseString(epp.uris(), ",", " ", "\t");
                if (methodCheck) {
                    if (uris.length != 1)
                        throw new IllegalArgumentException(epp.name() + ": invalid configuration only one URI can be associated with a method " + Arrays.toString(uris));
                }
                hep.setPaths(uris);

            } else if (a instanceof SecurityProp) {
//                SecurityProp sp = (SecurityProp) a;
//
//                String[] roles = SUS.isEmpty(sp.roles()) ? null : SharedStringUtil.parseString(sp.roles(), ",", " ", "\t");
//                String[] permissions = SUS.isEmpty(sp.permissions()) ? null : SharedStringUtil.parseString(sp.permissions(), ",", " ", "\t");
//                CryptoConst.AuthenticationType[] authTypes = sp.authentications();
//                String[] restrictions = sp.restrictions().length > 0 ? sp.restrictions() : null;
//                hep.setPermissions(permissions);
//                hep.setRoles(roles);
//                hep.setAuthenticationTypes(authTypes);
//                hep.setRestrictions(restrictions);
//                hep.setProtocols(sp.protocols());
                SecUtil.SINGLETON.applySecurityProp(hep, (SecurityProp) a);
            }
        }
        return updatePaths(baseURI, hep);
    }


//    public static void applySecurityProp(HTTPEndPoint hep, SecurityProp sp)
//    {
//        if (hep != null && sp != null)
//        {
//            String[] roles = SUS.isEmpty(sp.roles()) ? null : SharedStringUtil.parseString(sp.roles(), ",", " ", "\t");
//            String[] permissions = SUS.isEmpty(sp.permissions()) ? null : SharedStringUtil.parseString(sp.permissions(), ",", " ", "\t");
//            CryptoConst.AuthenticationType[] authTypes = sp.authentications();
//            String[] restrictions = sp.restrictions().length > 0 ? sp.restrictions() : null;
//            hep.setPermissions(permissions);
//            hep.setRoles(roles);
//            hep.setAuthenticationTypes(authTypes);
//            hep.setRestrictions(restrictions);
//            hep.setProtocols(sp.protocols());
//        }
//    }

    public static HTTPEndPoint mergeOuterIntoInner(HTTPEndPoint outer, HTTPEndPoint inner, boolean pathOverride) {

        if (outer != null) {
            if (outer.getHTTPMethods() != null && outer.getHTTPMethods().length > 0)
                inner.setHTTPMethods(outer.getHTTPMethods());

//            if (pathOverride && outer.getPaths().length > 0)
//                inner.setPaths(outer.getPaths());
//            if (outer.getPermissions() != null && !outer.getPermissions().isEmpty())
//                inner.setPermissions(outer.permissions());
//            if (outer.getRoles() != null && outer.getRoles().size() > 0)
//                inner.setRoles(outer.roles());
//            if (outer.getAuthenticationTypes() != null && outer.getAuthenticationTypes().length > 0)
//                inner.setAuthenticationTypes(outer.getAuthenticationTypes());
//            if (outer.getRestrictions() != null && outer.getRestrictions().size() > 0)
//                inner.setRestrictions(outer.restrictions());
//            if (outer.getProtocols() != null && outer.getProtocols().length > 0)
//                inner.setProtocols(outer.getProtocols());


            if (pathOverride && SUS.isNotEmpty(outer.getPaths()))
                inner.setPaths(outer.getPaths());
            if (SUS.isNotEmpty(outer.getPermissions()))
                inner.setPermissions(outer.permissions());
            if (SUS.isNotEmpty(outer.getRoles()))
                inner.setRoles(outer.roles());
            if (SUS.isNotEmpty(outer.getAuthenticationTypes()))
                inner.setAuthenticationTypes(outer.getAuthenticationTypes());
            if (SUS.isNotEmpty(outer.getRestrictions()))
                inner.setRestrictions(outer.restrictions());
            if (SUS.isNotEmpty(outer.getProtocols()))
                inner.setProtocols(outer.getProtocols());

            inner.getProperties().add(outer.getProperties().values(), true);
        }

        return inner;
    }


    private static boolean scanWebSocket(String baseURI, EndPointsManager epm, Class<?> beanClass, Object beanInstance) {
        // scan the annotation
        ReflectionUtil.AnnotationMap classAnnotationMap = ReflectionUtil.scanClassAnnotations(beanClass,
                ServerEndpoint.class,
                OnMessage.class,
                OnOpen.class,
                OnClose.class,
                OnError.class,
                SecurityProp.class);

        if (classAnnotationMap != null) {
            ServerEndpoint serverWS = classAnnotationMap.findClassAnnotationByType(ServerEndpoint.class);
            if (serverWS != null) {
                SecurityProp sp = classAnnotationMap.findClassAnnotationByType(SecurityProp.class);
                log.getLogger().info("WebSocket server end point " + classAnnotationMap);
                log.getLogger().info("OnMessage: " + Arrays.toString(classAnnotationMap.findMethodAnnotationsByType(OnMessage.class)));
                String uri = updatePath(baseURI, serverWS.value());
                WSCache wsCache = new WSCache(beanClass);
                Object wsBean = epm.pic.newInstance(uri, sp, wsCache, beanInstance);


                log.getLogger().info(beanClass.getName() + "\nBy Method-CanID: " + WSCache.WSMethodType.matchClassMethodsByCanID(beanClass).keySet());
                // we have a server websocket class endpoint

                HTTPEndPoint hep = new HTTPEndPoint();
                hep.setBeanClassName(wsBean.getClass().getName());
                SecUtil.SINGLETON.applySecurityProp(hep, sp);
                //classHEP = applyAnnotations(baseURI, classHEP, classAnnotationMap.getClassAnnotations(), false);
                log.getLogger().info("Inner web socket " + wsBean.getClass());
                ReflectionUtil.AnnotationMap wsAnnotationMap = ReflectionUtil.scanClassAnnotations(wsBean.getClass(), EndPointProp.class);

                Map<Method, ReflectionUtil.MethodAnnotations> map = wsAnnotationMap.getMethodsAnnotations();

                epm.map(uri, hep, new MethodHolder(wsBean, map.values().iterator().next(), hep));

                log.getLogger().info("Inner websocket " + map);
                log.getLogger().info("CACHED Mapped Methods: " + wsCache.getCache());
                log.getLogger().info("CACHED Types: " + wsCache.getCache().size() + " " + wsCache.getCache().keySet());

                log.getLogger().info("______________________________________________________________________");


                return true;
            }
        }

        return false;
    }

    public static boolean areAllParametersUniquelyAnnotatedParamProp(ReflectionUtil.MethodAnnotations ma) {

        // check if the parameter count == parametersAnnotations.size()
        int parameterCount = ma.method.getParameterCount();
        int annotationCount = ma.parametersAnnotations != null ? ma.parametersAnnotations.size() : 0;
        if (parameterCount != annotationCount)
            throw new IllegalArgumentException("Annotated parameters not equals to actual parameters" + ma.method);

        if (annotationCount > 0) {
            // check that the annotation are of the type anotClass and uniquely named
            Set<String> annotParamNames = new HashSet<String>();
            for (Annotation a : ma.parametersAnnotations.values()) {
                if (a == null || !ReflectionUtil.isTypeMatchingAnyAnnotation(ParamProp.class, a))
                    throw new IllegalArgumentException("Parameter not annotated as " + ParamProp.class.getName());
                annotParamNames.add(((ParamProp) a).name());
            }

            if (annotationCount != annotParamNames.size())
                throw new IllegalArgumentException("Mismatch between annotations and parameters count could be repeated parameter name: " + ma.method);
        }


        return true;
    }

    public static EndPointsManager scan(HTTPServerConfig serverConfig, InstanceFactory.ParamsInstanceCreator<?> pic) {
        HTTPEndPoint[] allHEP = serverConfig.getEndPoints();
        EndPointsManager epm = new EndPointsManager(pic);
        for (HTTPEndPoint configHEP : allHEP) {

            // annotation override
            // If there is a conflict with annotation
            // the json config file will override the code defined one
            // this technique will allow configuration to be updated on the fly without the
            // need to recompile the code
            try {
                String beanName = configHEP.getBeanClassName();
                Class<?> beanClass = Class.forName(beanName);
                Object beanInstance = beanClass.getDeclaredConstructor().newInstance();
                if (log.isEnabled())
                    log.getLogger().info("bean:" + beanName + " " + beanInstance + " " + allHEP.length);

                if (beanInstance instanceof SetNVProperties) {
                    ((SetNVProperties) beanInstance).setProperties(configHEP.getProperties());
                }

                if (log.isEnabled()) log.getLogger().info("bean:" + beanName);
                if (!scanWebSocket(serverConfig.getBaseURI(), epm, beanClass, beanInstance)) {
                    if (log.isEnabled()) log.getLogger().info("Scan the class");
                    ReflectionUtil.AnnotationMap classAnnotationMap = ReflectionUtil.scanClassAnnotations(beanClass, MappedProp.class);
                    // --- Map the bean to the mapped id
                    if (classAnnotationMap != null && SUS.isNotEmpty(classAnnotationMap.getClassAnnotations())) {
                        epm.mapBean(beanInstance, classAnnotationMap.getClassAnnotations()[0]);
                    } else {
                        epm.mapBean(beanInstance, null);
                    }
                    // ---

                    // -- process the rest of the annotations
                    classAnnotationMap = ReflectionUtil.scanClassAnnotations(beanClass, EndPointProp.class, SecurityProp.class, ParamProp.class);


                    //if(log.isEnabled()) log.getLogger().info("Class Annotation:" + classAM);
                    if (classAnnotationMap != null) {
                        HTTPEndPoint classHEP = null;


                        if (classAnnotationMap.getClassAnnotations() != null) {
                            classHEP = new HTTPEndPoint();
                            classHEP.setBeanClassName(beanName);
                            classHEP = applyAnnotations(serverConfig.getBaseURI(), classHEP, classAnnotationMap.getClassAnnotations(), false);
                            classHEP = mergeOuterIntoInner(configHEP, classHEP, false);

                        } else {
                            if (log.isEnabled())
                                log.getLogger().info(classAnnotationMap.getAnnotatedClass() + " has no class annotations");
                        }
                        if (classAnnotationMap.getMethodsAnnotations().size() > 0) {
                            for (Method method : classAnnotationMap.getMethodsAnnotations().keySet().toArray(new Method[0])) {

                                ReflectionUtil.MethodAnnotations methodAnnotations = classAnnotationMap.getMethodsAnnotations().get(method);
                                try {
                                    //if (ReflectionUtil.isMethodAnnotatedAs(method, EndPointProp.class))
                                    if (areAllParametersUniquelyAnnotatedParamProp(methodAnnotations)) {

                                        HTTPEndPoint methodHEP = applyAnnotations(serverConfig.getBaseURI(),
                                                new HTTPEndPoint(),
                                                methodAnnotations.methodAnnotations(),
                                                true);

                                        methodHEP = mergeOuterIntoInner(classHEP, methodHEP, false);

                                        mapHEP(epm, methodHEP, new MethodHolder(beanInstance, methodAnnotations, methodHEP));

                                    } else {
                                        if (log.isEnabled())
                                            log.getLogger().info(methodAnnotations.method + " NOT-AN-ENDPOINT");
                                    }
                                } catch (Exception e) {
                                    e.printStackTrace();
                                    if (log.isEnabled())
                                        log.getLogger().info("Method:" + method + " failed to configure");
                                }
                            }
                        }
                    }

                }

            } catch (Exception e) {
                e.printStackTrace();
            }
        }


        // scan onStartup and OnShutdown
        NVGenericMap startup = serverConfig.getProperties().getNV("on-startup");
        NVGenericMap shutdown = serverConfig.getProperties().getNV("on-shutdown");
        log.getLogger().info("startup config: " + startup + " shutdown config: " + shutdown);

        if (startup != null) {
            try {
                Class<?> clazz = Class.forName(startup.getValue("bean"));
                ReflectionUtil.AnnotationMap onStartup = ReflectionUtil.scanClassAnnotations(clazz, OnStartup.class);
                if (onStartup != null) {
                    epm.onStartup = new MethodHolder(clazz.getConstructor().newInstance(), onStartup.findMethodAnnotationsByType(OnStartup.class)[0], null);
                }

            } catch (Exception e) {
                e.printStackTrace();
            }

        }

        if (shutdown != null) {
            try {
                Class<?> clazz = Class.forName(startup.getValue("bean"));
                ReflectionUtil.AnnotationMap onShutdown = ReflectionUtil.scanClassAnnotations(clazz, OnShutdown.class);
                if (onShutdown != null) {
                    epm.onShutdown = new MethodHolder(clazz.getConstructor().newInstance(), onShutdown.findMethodAnnotationsByType(OnStartup.class)[0], null);
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        log.getLogger().info("@OnStartup: " + epm.onStartup + " @OnShutdown: " + epm.onShutdown);


        return epm;
    }


    private static void mapHEP(EndPointsManager endPointsManager, HTTPEndPoint hep, MethodHolder methodHolder) {
        for (String path : hep.getPaths()) {
            String pathToBeAdded = HTTPUtil.basePath(path, true);
            endPointsManager.map(pathToBeAdded, hep, methodHolder);
            if (log.isEnabled()) log.getLogger().info(pathToBeAdded + ":" + hep);
        }
    }


    public static Map<String, Object> buildParameters(URIMap.URIMapResult<EndPointMeta> uriMapResult, HTTPMessageConfigInterface hmci) throws IOException {

        HTTPEndPoint hep = uriMapResult.result.httpEndPoint;


//        if (!hep.isPathSupported(hmci.getURI()))
//        {
//            throw new IOException("Invalid uri " + hmci.getURI());
//        }
        // parse the path parameters
        Map<String, Object> parameters = HTTPUtil.parsePathParameters(hep.getPaths()[0], hmci.getURI(), false);

        if (hmci.getParameters().size() > 0) {
            GetNameValue<?>[] gnValues = hmci.getParameters().values();
            for (GetNameValue<?> gnv : hmci.getParameters().values()) {
                parameters.put(gnv.getName(), gnv.getValue());
            }
        }


        HTTPMediaType contentType = HTTPMediaType.lookup(hmci.getContentType());

//        String  payload = null;
        // parse if not post for n=v&n2=v2 body
//        if (!he.getRequestMethod().equalsIgnoreCase(HTTPMethod.GET.getName()) && contentType == HTTPMediaType.APPLICATION_WWW_URL_ENC)
//        {
//            payload = IOUtil.inputStreamToString(he.getRequestBody(), true);
//            List<GetNameValue<String>> payloadParameters = HTTPUtil.parseQuery(payload, false);
//
//            if(payloadParameters != null && payloadParameters.size() > 0)
//            {
//                for(GetNameValue<String> gnv : payloadParameters)
//                    parameters.put(gnv.getName(), gnv.getValue());
//            }
//        }
//        else if (contentType == HTTPMediaType.APPLICATION_JSON)
//        {
//            payload = IOUtil.inputStreamToString(he.getRequestBody(), true);
//        }
        //if(log.isEnabled()) log.getLogger().info("payload:" + payload);


        // need to parse the payload parameters
        for (Parameter p : uriMapResult.result.methodHolder.methodAnnotations.method.getParameters()) {
            Annotation pAnnotation = uriMapResult.result.methodHolder.methodAnnotations.parametersAnnotations.get(p);
            if (pAnnotation instanceof ParamProp) {
                ParamProp pp = (ParamProp) pAnnotation;
                if (pp.uri()) {
                    parameters.put(pp.name(), hmci.getURI());
                    if (log.isEnabled()) log.getLogger().info("we have a uri " + pp.name() + " " + parameters);
                    continue;
                }

                if (pp.source() == Const.ParamSource.PAYLOAD) {
                    Class<?> pClassType = p.getType();
                    if (contentType != null) {

                        switch (contentType) {

                            case APPLICATION_WWW_URL_ENC:
                                // this case is impossible to happen
                                break;
                            case APPLICATION_JSON:
                                if (log.isEnabled()) {
                                    log.getLogger().info("" + hmci);
                                    log.getLogger().info("" + pClassType);
                                }
                                Object v = GSONUtil.fromJSONDefault(hmci.getContent(), pClassType);
                                parameters.put(pp.name(), v);


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

                // check if null and optional
                Object currentValue = parameters.get(pp.name());

                if (currentValue == null) {
                    if (pp.optional()) {
                        if (SharedUtil.isPrimitive(p.getType())) {
                            NVBase<?> paramValue = SharedUtil.classToNVBase(p.getType(), pp.name(), null);
                            parameters.put(pp.name(), paramValue != null ? paramValue.getValue() : null);
                        }
                        continue;
                    } else {
                        throw new IllegalArgumentException("Missing parameter " + pp.name());
                    }
                }

                if (SharedUtil.isPrimitive(p.getType()) || Enum.class.isAssignableFrom(p.getType()) || Enum[].class.isAssignableFrom(p.getType())) {
                    parameters.put(pp.name(), SharedUtil.classToNVBase(p.getType(), pp.name(), (String) currentValue).getValue());
                }
            }
        }

        return parameters;
    }


    public MethodHolder getOnStartup() {
        return onStartup;
    }

    public MethodHolder getOnShutdown() {
        return onShutdown;
    }
}
