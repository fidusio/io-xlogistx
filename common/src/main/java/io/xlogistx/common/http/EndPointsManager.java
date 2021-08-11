package io.xlogistx.common.http;


import io.xlogistx.common.data.MethodHolder;

import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.util.ReflectionUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.http.HTTPEndPoint;
import org.zoxweb.shared.http.HTTPServerConfig;
import org.zoxweb.shared.security.SecurityConsts;
import org.zoxweb.shared.util.SetNVProperties;
import org.zoxweb.shared.util.SharedStringUtil;
import org.zoxweb.shared.util.SharedUtil;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.*;
import java.util.logging.Logger;

public class EndPointsManager {

    private final static Logger log = Logger.getLogger(EndPointsManager.class.getName());

    public static class EndPointMeta
    {
        public final HTTPEndPoint httpEndPoint;
        public final MethodHolder methodHolder;
        private EndPointMeta(HTTPEndPoint hep, MethodHolder mh)
        {

            this.httpEndPoint = hep;
            this.methodHolder = mh;
        }
    }

    private Map<String, EndPointMeta> uriEndPointMeta = new LinkedHashMap<String, EndPointMeta>();

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
        return uriEndPointMeta.remove(SharedStringUtil.toTrimmedLowerCase(uri));
    }

    public EndPointMeta lookup(String uri)
    {
        return uriEndPointMeta.get(SharedStringUtil.toTrimmedLowerCase(uri));
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
                String[] permissions = SharedStringUtil.isEmpty(sp.permissions()) ? null : SharedStringUtil.parseString(sp.permissions(), ",", " ", "\t");;
                SecurityConsts.AuthenticationType[] authTypes = sp.authentications();
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
            // this technique will allow configuration to updated on the fly without the
            // need to recompile the code
            try
            {
                String beanName = configHEP.getBean();
                Class<?> beanClass = Class.forName(beanName);
                Object beanInstance = beanClass.getDeclaredConstructor().newInstance();
                log.info("bean:" + beanName + " " + beanInstance + " " + allHEP.length);

                if(beanInstance instanceof SetNVProperties)
                {
                    ((SetNVProperties) beanInstance).setProperties(configHEP.getProperties());
                }

                log.info("bean:" + beanName);

                {
                    log.info("Scan the class");
                    ReflectionUtil.AnnotationMap classAnnotationMap = ReflectionUtil.scanClassAnnotations(beanClass, EndPointProp.class, SecurityProp.class, ParamProp.class);

                    //log.info("Class Annotation:" + classAM);
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
                            log.info("" + classAnnotationMap.getAnnotatedClass() + "has no class annotations");
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
                                        log.info(methodAnnotations.method + " NOT-AN-ENDPOINT");
                                    }
                                }
                                catch(Exception e)
                                {
                                    e.printStackTrace();
                                    log.info("Method:" + method + " failed to configure");
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
            log.info(pathToBeAdded  + ":"+ hep);
        }
    }
}
