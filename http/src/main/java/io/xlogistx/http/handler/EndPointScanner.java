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
                    ReflectionUtil.AnnotationMap classAM = ReflectionUtil.scanClassAnnotations(beanClass, EndPointProp.class, SecurityProp.class, ParamProp.class);

                    //log.info("Class Annotation:" + classAM);
                    if (classAM != null)
                    {
                        HTTPEndPoint classHEP = null;


                        if (classAM.getClassAnnotations() != null)
                        {
                            classHEP = new HTTPEndPoint();
                            classHEP.setBean(beanName);
                            classHEP = scanAnnotations(serverConfig.getBaseURI(), classHEP, classAM.getClassAnnotations());
                            classHEP = mergeOuterIntoInner(configHEP, classHEP);

                        }
                        else
                        {
                            log.info("" + classAM.getAnnotatedClass() + "has no class annotations");
                        }
                        if (classAM.getMethodsAnnotations().size() > 0)
                        {
                            for (Method method : classAM.getMethodsAnnotations().keySet().toArray(new Method[0]))
                            {

                                ReflectionUtil.MethodAnnotations methodAnnotations = classAM.getMethodsAnnotations().get(method);
                                if (ReflectionUtil.isMethodAnnotatedAs(method, EndPointProp.class))
                                {
                                    HTTPEndPoint methodHEP = scanAnnotations(serverConfig.getBaseURI(),
                                                                             new HTTPEndPoint(),
                                                                             methodAnnotations.methodAnnotations);

                                    methodHEP = mergeOuterIntoInner(classHEP, methodHEP);

                                    EndPointHandler endPointHandler = new EndPointHandler(beanInstance, methodAnnotations);
                                    endPointHandler.setHTTPEndPoint(methodHEP);
                                    for (HttpServer hs : httpServers)
                                    {
                                        for (String path : methodHEP.getPaths())
                                        {
                                            String pathToBeAdded = HTTPUtil.basePath(path, false);
                                            HttpContext httpContext = hs.createContext(pathToBeAdded);
                                            httpContext.setHandler(endPointHandler);
                                            log.info("["+endPointHandler.ID+"] :" + endPointHandler.getHTTPEndPoint());
                                        }
                                    }

                                }
                                else
                                {
                                    log.info(methodAnnotations.method + " NOT-AN-ENDPOINT");
                                }
                            }





//                            classAM.getMethodsAnnotations().forEach(new BiConsumer<Method, ReflectionUtil.MethodAnnotations>() {
//                                @Override
//                                public void accept(Method method, ReflectionUtil.MethodAnnotations ma) {
//                                    // parse the method annotations
//                                    if (HTTPHandlerUtil.isMethodParameterAnnotated(ma, ParamProp.class))
//                                    {
//                                        for (Annotation a : ma.methodAnnotations) {
//                                            if (a instanceof EndPointProp) {
//                                                EndPointProp epp = (EndPointProp) a;
//
//                                                innerHep.setName(epp.name());
//
//                                                innerHep.setMethods(epp.methods());
//                                                innerHep.setPaths(SharedStringUtil.parseString(epp.uris(), ",", " ", "\t"));
//                                            } else if (a instanceof SecurityProp) {
//                                                SecurityProp sp = (SecurityProp) a;
//
//                                                String[] roles = SharedStringUtil.isEmpty(sp.roles()) ? null : SharedStringUtil.parseString(sp.roles(), ",", " ", "\t");
//                                                String[] permissions = SharedStringUtil.isEmpty(sp.permissions()) ? null : SharedStringUtil.parseString(sp.permissions(), ",", " ", "\t");
//                                                ;
//                                                AuthenticationType[] authTypes = sp.authentications();
//                                                String[] restrictions = sp.restrictions().length > 0 ? sp.restrictions() : null;
//                                                innerHep.setPermissions(permissions);
//                                                innerHep.setRoles(roles);
//                                                innerHep.setAuthenticationTypes(authTypes);
//                                                innerHep.setRestrictions(restrictions);
//                                            }
//                                        }
//                                        mergeOuterIntoInner(outerHep, innerHep);
//
//                                        EndPointHandler endPointHandler = new EndPointHandler(bean, classAM, ma);
//                                        endPointHandler.setHTTPEndPoint(innerHep);
//                                        for (HttpServer hs : httpServers) {
//                                            for (String path : innerHep.getPaths()) {
//
//                                                String pathToBeAdded = HTTPUtil.basePath(path, true);
//                                                log.info("Original Path: " + path + " Path to be added: " + pathToBeAdded + " innerhep:" + innerHep + " " + ma) ;
//                                                HttpContext httpContext = hs.createContext(pathToBeAdded, endPointHandler);
//                                                //httpContext.setAuthenticator()
//                                            }
//                                        }
//
//                                    }
//                                    else
//                                    {
//                                        log.info(ma.method + " has some parameters NOT ANNOTATED");
//                                    }
//                                }
//                            });

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



    private static HTTPEndPoint scanAnnotations(String baseURI, HTTPEndPoint hep, Annotation[] annotations)
    {
        for (Annotation a : annotations) {
            if (a instanceof EndPointProp) {
                EndPointProp epp = (EndPointProp) a;
                hep.setName(epp.name());
                hep.setMethods(epp.methods());
                hep.setPaths(SharedStringUtil.parseString(epp.uris(), ",", " ", "\t"));
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
