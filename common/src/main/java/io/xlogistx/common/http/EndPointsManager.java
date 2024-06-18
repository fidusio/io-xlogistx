package io.xlogistx.common.http;


import io.xlogistx.common.data.MethodHolder;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.server.util.ReflectionUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.http.HTTPEndPoint;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;
import org.zoxweb.shared.http.HTTPMediaType;
import org.zoxweb.shared.http.HTTPServerConfig;
import org.zoxweb.shared.util.*;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class EndPointsManager {

    public final static LogWrapper log = new LogWrapper(EndPointsManager.class).setEnabled(false);


    //private Map<String, EndPointMeta> uriEndPointMeta = new LinkedHashMap<String, EndPointMeta>();

    private final URIMap<EndPointMeta> uriEndPointMeta = new URIMap<>();

    public synchronized EndPointMeta map(String uri, HTTPEndPoint hep, MethodHolder mh)
    {
        uri = SharedStringUtil.toTrimmedLowerCase(uri);
        SharedUtil.checkIfNulls("Mapping parameters can't be null", uri, hep);
        EndPointMeta epm = new EndPointMeta(hep, mh);
        uriEndPointMeta.put(uri, epm);
        return epm;
    }


    public EndPointMeta unmap(String uri)
    {
        return uriEndPointMeta.remove(uri);
    }

    public EndPointMeta lookup(String uri)
    {
        return uriEndPointMeta.lookup(uri);
    }

    public  URIMap.URIMapResult<EndPointMeta> lookupWithPath(String uri)
    {
        return uriEndPointMeta.lookupWithPath(uri);
    }

    public static HTTPEndPoint updatePaths(String baseURI, HTTPEndPoint hep)
    {
        baseURI = SharedStringUtil.trimOrNull(baseURI);
        if(baseURI != null)
        {
            String[] paths = hep.getPaths();
            for(int i = 0; i < paths.length; i++)
            {
                paths[i] = SharedStringUtil.concat(baseURI, paths[i], "/");
            }
            hep.setPaths(paths);
        }
        return hep;
    }

    public static HTTPEndPoint scanAnnotations(String baseURI, HTTPEndPoint hep, Annotation[] annotations, boolean methodCheck)
    {
        for (Annotation a : annotations) {
            if (a instanceof EndPointProp) {
                EndPointProp epp = (EndPointProp) a;
                hep.setName(epp.name());
                hep.setDescription(epp.description());
                hep.setMethods(epp.methods());
                hep.setInputContentType(epp.iContentType());
                hep.setOutputContentType(epp.oContentType());

                String [] uris = SharedStringUtil.parseString(epp.uris(), ",", " ", "\t");
                if(methodCheck)
                {
                    if(uris.length != 1)
                        throw  new IllegalArgumentException(epp.name() + ": invalid configuration only one URI can be associated with a method " + Arrays.toString(uris));
                }
                hep.setPaths(uris);

            } else if (a instanceof SecurityProp) {
                SecurityProp sp = (SecurityProp) a;

                String[] roles = SharedStringUtil.isEmpty(sp.roles()) ? null : SharedStringUtil.parseString(sp.roles(), ",", " ", "\t");
                String[] permissions = SharedStringUtil.isEmpty(sp.permissions()) ? null : SharedStringUtil.parseString(sp.permissions(), ",", " ", "\t");
                CryptoConst.AuthenticationType[] authTypes = sp.authentications();
                String[] restrictions = sp.restrictions().length > 0 ? sp.restrictions() : null;
                hep.setPermissions(permissions);
                hep.setRoles(roles);
                hep.setAuthenticationTypes(authTypes);
                hep.setRestrictions(restrictions);
                hep.setProtocols(sp.protocols());
            }
        }
        return updatePaths(baseURI, hep);
    }

    public static HTTPEndPoint mergeOuterIntoInner(HTTPEndPoint outer, HTTPEndPoint inner, boolean pathOverride)
    {

        if(outer != null) {
            if (outer.getMethods() != null && outer.getMethods().length > 0)
                inner.setMethods(outer.getMethods());

            if (pathOverride && outer.getPaths().length > 0)
                inner.setPaths(outer.getPaths());
            if (outer.getPermissions() != null && outer.getPermissions().length > 0)
                inner.setPermissions(outer.getPermissions());
            if (outer.getRoles() != null && outer.getRoles().length > 0)
                inner.setRoles(outer.getRoles());
            if (outer.getAuthenticationTypes() != null && outer.getAuthenticationTypes().length > 0)
                inner.setAuthenticationTypes(outer.getAuthenticationTypes());
            if (outer.getRestrictions() != null && outer.getRestrictions().length > 0)
                inner.setRestrictions(outer.getRestrictions());
            if (outer.getProtocols() != null && outer.getProtocols().length > 0)
                inner.setProtocols(outer.getProtocols());

            inner.getProperties().add(outer.getProperties().values(), true);
        }

        return inner;
    }

    public static boolean areAllParametersUniquelyAnnotatedParamProp(ReflectionUtil.MethodAnnotations ma)
    {

        // check if the parameter count == parametersAnnotations.size()
        int parameterCount = ma.method.getParameterCount();
        int annotationCount = ma.parametersAnnotations != null ? ma.parametersAnnotations.size() : 0;
        if(parameterCount != annotationCount)
            throw new IllegalArgumentException("Annotated parameters not equals to actual parameters" + ma.method);

        if(annotationCount > 0)
        {
            // check that the annotation are of the type anotClass and uniquely named
            Set<String> annotParamNames = new HashSet<String>();
            for(Annotation a : ma.parametersAnnotations.values())
            {
                if(a == null || !ReflectionUtil.isTypeMatchingAnyAnnotation(ParamProp.class, a))
                    throw new IllegalArgumentException("Parameter not annotated as " + ParamProp.class.getName());
                annotParamNames.add(((ParamProp)a).name());
            }

            if(annotationCount != annotParamNames.size())
                throw new IllegalArgumentException("Mismatch between annotations and parameters count could be repeated parameter name: " + ma.method);
        }


        return true;
    }

    public static EndPointsManager scan(HTTPServerConfig serverConfig)
    {
        HTTPEndPoint[] allHEP = serverConfig.getEndPoints();
        EndPointsManager ret = new EndPointsManager();
        for(HTTPEndPoint configHEP : allHEP)
        {

            // annotation override
            // If there is a conflict with annotation
            // the json config file will override the code defined one
            // this technique will allow configuration to be updated on the fly without the
            // need to recompile the code
            try
            {
                String beanName = configHEP.getBean();
                Class<?> beanClass = Class.forName(beanName);
                Object beanInstance = beanClass.getDeclaredConstructor().newInstance();
                if(log.isEnabled()) log.getLogger().info("bean:" + beanName + " " + beanInstance + " " + allHEP.length);

                if(beanInstance instanceof SetNVProperties)
                {
                    ((SetNVProperties) beanInstance).setProperties(configHEP.getProperties());
                }

                if(log.isEnabled()) log.getLogger().info("bean:" + beanName);

                {
                    if(log.isEnabled()) log.getLogger().info("Scan the class");
                    ReflectionUtil.AnnotationMap classAnnotationMap = ReflectionUtil.scanClassAnnotations(beanClass, EndPointProp.class, SecurityProp.class, ParamProp.class);

                    //if(log.isEnabled()) log.getLogger().info("Class Annotation:" + classAM);
                    if (classAnnotationMap != null)
                    {
                        HTTPEndPoint classHEP = null;


                        if (classAnnotationMap.getClassAnnotations() != null)
                        {
                            classHEP = new HTTPEndPoint();
                            classHEP.setBean(beanName);
                            classHEP = scanAnnotations(serverConfig.getBaseURI(), classHEP, classAnnotationMap.getClassAnnotations(), false);
                            classHEP = mergeOuterIntoInner(configHEP, classHEP, false);

                        }
                        else
                        {
                            if(log.isEnabled()) log.getLogger().info("" + classAnnotationMap.getAnnotatedClass() + "has no class annotations");
                        }
                        if (classAnnotationMap.getMethodsAnnotations().size() > 0)
                        {
                            for (Method method : classAnnotationMap.getMethodsAnnotations().keySet().toArray(new Method[0]))
                            {

                                ReflectionUtil.MethodAnnotations methodAnnotations = classAnnotationMap.getMethodsAnnotations().get(method);
                                try {
                                    //if (ReflectionUtil.isMethodAnnotatedAs(method, EndPointProp.class))
                                    if (areAllParametersUniquelyAnnotatedParamProp(methodAnnotations))
                                    {

                                        HTTPEndPoint methodHEP = scanAnnotations(serverConfig.getBaseURI(),
                                                new HTTPEndPoint(),
                                                methodAnnotations.methodAnnotations,
                                                true);

                                        methodHEP = mergeOuterIntoInner(classHEP, methodHEP, false);

                                        mapHEP(ret, methodHEP, new MethodHolder(beanInstance, methodAnnotations));

                                    } else {
                                        if(log.isEnabled()) log.getLogger().info(methodAnnotations.method + " NOT-AN-ENDPOINT");
                                    }
                                }
                                catch(Exception e)
                                {
                                    e.printStackTrace();
                                    if(log.isEnabled()) log.getLogger().info("Method:" + method + " failed to configure");
                                }
                            }
                        }
                    }

                }

            }
            catch(Exception e)
            {
                e.printStackTrace();
            }
        }


        return ret;
    }


    private static void mapHEP(EndPointsManager endPointsManager,HTTPEndPoint hep, MethodHolder methodHolder)
    {
        for (String path : hep.getPaths())
        {
            String pathToBeAdded = HTTPUtil.basePath(path, true);
            endPointsManager.map(pathToBeAdded, hep, methodHolder);
            if(log.isEnabled()) log.getLogger().info(pathToBeAdded  + ":"+ hep);
        }
    }


    public static Map<String, Object> buildParameters(URIMap.URIMapResult<EndPointMeta>uriMapResult, HTTPMessageConfigInterface hmci) throws IOException {

        HTTPEndPoint hep = uriMapResult.result.httpEndPoint;


//        if (!hep.isPathSupported(hmci.getURI()))
//        {
//            throw new IOException("Invalid uri " + hmci.getURI());
//        }
        // parse the path parameters
        Map<String, Object> parameters = HTTPUtil.parsePathParameters(hep.getPaths()[0], hmci.getURI(), false);

        if(hmci.getParameters().size() > 0)
        {
            GetNameValue<?>[] gnValues = hmci.getParameters().values();
            for (GetNameValue<?> gnv :  hmci.getParameters().values())
            {
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
        for(Parameter p : uriMapResult.result.methodHolder.getMethodAnnotations().method.getParameters())
        {
            Annotation pAnnotation  = uriMapResult.result.methodHolder.getMethodAnnotations().parametersAnnotations.get(p);
            if(pAnnotation != null  && pAnnotation instanceof ParamProp)
            {
                ParamProp pp = (ParamProp) pAnnotation;
                if (pp.source() == Const.ParamSource.PAYLOAD)
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
                                if(log.isEnabled())
                                {
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
                    }
                    else
                        throw new IllegalArgumentException("Missing parameter " + pp.name());
                }

                if(SharedUtil.isPrimitive(p.getType()) || Enum.class.isAssignableFrom(p.getType()) || Enum[].class.isAssignableFrom(p.getType()))
                {
                    parameters.put(pp.name(), SharedUtil.classToNVBase(p.getType(), pp.name(), (String)currentValue).getValue());
                }
            }
        }

        return parameters;
    }
}
