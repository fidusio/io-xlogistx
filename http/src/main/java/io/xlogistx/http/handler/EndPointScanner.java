package io.xlogistx.http.handler;

import com.sun.net.httpserver.HttpContext;

import com.sun.net.httpserver.HttpServer;
import io.xlogistx.http.HTTPBasicServer;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.util.ReflectionUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.http.HTTPEndPoint;
import org.zoxweb.shared.http.HTTPServerConfig;
import org.zoxweb.shared.security.SecurityConsts.AuthenticationType;
import org.zoxweb.shared.util.SetNVProperties;
import org.zoxweb.shared.util.SharedStringUtil;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.logging.Logger;

public class EndPointScanner
{

    private static transient Logger log = Logger.getLogger(EndPointScanner.class.getName());
    private final HTTPServerConfig serverConfig;
    private final HTTPBasicServer server;

    public EndPointScanner(HTTPServerConfig serverConfig, HTTPBasicServer server)
    {
        this.serverConfig = serverConfig;
        this.server = server;
    }


    public void scan()
    {
        HttpServer[] httpServers = server.getHttpServers();
        for(HTTPEndPoint configHEP : serverConfig.getEndPoints())
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
                BaseEndPointHandler beph = null;
                if(beanInstance instanceof SetNVProperties)
                {
                    ((SetNVProperties) beanInstance).setProperties(configHEP.getProperties());
                }

                log.info("bean:" + beanName);
                if (beanInstance instanceof BaseEndPointHandler)
                {
                    // we just create the context

                    //
                    beph = (BaseEndPointHandler) beanInstance;
                    beph.setHTTPEndPoint(configHEP);
                    // append the base_uri
                    configHEP = updatePaths(serverConfig.getBaseURI(), configHEP);
                    for (HttpServer hs : httpServers)
                    {
                        for (String path : configHEP.getPaths())
                            hs.createContext(path, beph);
                    }
                }
                else
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
                            classHEP = mergeOuterIntoInner(configHEP, classHEP);

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
                                    if (ReflectionUtil.isMethodAnnotatedAs(method, EndPointProp.class)) {
                                        HTTPEndPoint methodHEP = scanAnnotations(serverConfig.getBaseURI(),
                                                new HTTPEndPoint(),
                                                methodAnnotations.methodAnnotations,
                                                true);

                                        methodHEP = mergeOuterIntoInner(classHEP, methodHEP);

                                        EndPointHandler endPointHandler = new EndPointHandler(beanInstance, methodAnnotations);
                                        endPointHandler.setHTTPEndPoint(methodHEP);
                                        for (HttpServer hs : httpServers) {
                                            for (String path : methodHEP.getPaths()) {
                                                String pathToBeAdded = HTTPUtil.basePath(path, false);
                                                HttpContext httpContext = hs.createContext(pathToBeAdded);
                                                httpContext.setHandler(endPointHandler);
                                                log.info("[" + endPointHandler.ID + "] :" + endPointHandler.getHTTPEndPoint());
                                            }
                                        }

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
    }



    private static HTTPEndPoint scanAnnotations(String baseURI, HTTPEndPoint hep, Annotation[] annotations, boolean methodCheck)
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
                AuthenticationType[] authTypes = sp.authentications();
                String[] restrictions = sp.restrictions().length > 0 ? sp.restrictions() : null;
                hep.setPermissions(permissions);
                hep.setRoles(roles);
                hep.setAuthenticationTypes(authTypes);
                hep.setRestrictions(restrictions);
            }
        }
        return updatePaths(baseURI, hep);
    }


    private static HTTPEndPoint mergeOuterIntoInner(HTTPEndPoint outer, HTTPEndPoint inner)
    {

        if(outer != null) {
            if (outer.getMethods() != null && outer.getMethods().length > 0)
                inner.setMethods(outer.getMethods());
//
//        if (outer.getPaths().length > 0)
//            inner.setPaths(outer.getPaths());
            if (outer.getPermissions() != null && outer.getPermissions().length > 0)
                inner.setPermissions(outer.getPermissions());
            if (outer.getRoles() != null && outer.getRoles().length > 0)
                inner.setRoles(outer.getRoles());
            if (outer.getAuthenticationTypes() != null && outer.getAuthenticationTypes().length > 0)
                inner.setAuthenticationTypes(outer.getAuthenticationTypes());
            if (outer.getRestrictions() != null && outer.getRestrictions().length > 0)
                inner.setRestrictions(outer.getRestrictions());

            inner.getProperties().add(outer.getProperties().values(), true);
        }

        return inner;
    }


    private static HTTPEndPoint updatePaths(String baseURI, HTTPEndPoint hep)
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



}
