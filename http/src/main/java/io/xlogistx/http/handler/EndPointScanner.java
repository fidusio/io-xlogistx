package io.xlogistx.http.handler;

import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpHandler;
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
import java.util.function.BiConsumer;
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
        for(HTTPEndPoint outerHep : serverConfig.getEndPoints())
        {

            // annotation override
            // If there is a conflict with annotation
            // the json config file will override the code defined one
            // this technique will allow configuration to updated on the fly without the
            // need to recompile the code
            try
            {
                String beanName = outerHep.getBean();
                Class<?> beanClass = Class.forName(beanName);
                Object bean = beanClass.getDeclaredConstructor().newInstance();
                BaseEndPointHandler beph = null;

                log.info("bean:" + beanName);
                if (bean instanceof BaseEndPointHandler)
                {
                    // we just create the context

                    //
                    beph = (BaseEndPointHandler) bean;
                    beph.setHTTPEndPoint(outerHep);

                    for (HttpServer hs : httpServers)
                    {
                        for (String path : outerHep.getPaths())
                            hs.createContext(path, beph);
                    }
                }
                else
                {
                    log.info("Scan the class");
                    ReflectionUtil.AnnotationMap am = ReflectionUtil.scanClassAnnotations(beanClass, EndPointProp.class, SecurityProp.class, ParamProp.class);

                    log.info("" + am);
                    if (am != null)
                    {
                        HTTPEndPoint innerHep = new HTTPEndPoint();
                        if (am.getClassAnnotations()!=null)
                        {
                            // we have class annotations
                        }
                        else
                        {
                            log.info("" + am.getAnnotatedClass() + " has no class annotations");
                        }
                        if (am.getMethodsAnnotations().size() > 0)
                        {
                            am.getMethodsAnnotations().forEach(new BiConsumer<Method, ReflectionUtil.MethodAnnotations>() {
                                @Override
                                public void accept(Method method, ReflectionUtil.MethodAnnotations ma) {
                                    // parse the method annotations
                                    if (HTTPHandlerUtil.isMethodParameterAnnotated(ma, ParamProp.class))
                                    {
                                        for (Annotation a : ma.methodAnnotations) {
                                            if (a instanceof EndPointProp) {
                                                EndPointProp epp = (EndPointProp) a;

                                                innerHep.setName(epp.name());

                                                innerHep.setMethods(epp.methods());
                                                innerHep.setPaths(SharedStringUtil.parseString(epp.uris(), ",", " ", "\t"));
                                            } else if (a instanceof SecurityProp) {
                                                SecurityProp sp = (SecurityProp) a;

                                                String[] roles = SharedStringUtil.isEmpty(sp.roles()) ? null : SharedStringUtil.parseString(sp.roles(), ",", " ", "\t");
                                                String[] permissions = SharedStringUtil.isEmpty(sp.permissions()) ? null : SharedStringUtil.parseString(sp.permissions(), ",", " ", "\t");
                                                ;
                                                AuthenticationType[] authTypes = sp.authentications();
                                                String[] restrictions = sp.restrictions().length > 0 ? sp.restrictions() : null;
                                                innerHep.setPermissions(permissions);
                                                innerHep.setRoles(roles);
                                                innerHep.setAuthenticationTypes(authTypes);
                                                innerHep.setRestrictions(restrictions);
                                            }
                                        }
                                        mergeOuterIntoInner(outerHep, innerHep);

                                        EndPointHandler endPointHandler = new EndPointHandler(bean, am);
                                        endPointHandler.setHTTPEndPoint(innerHep);
                                        for (HttpServer hs : httpServers) {
                                            for (String path : innerHep.getPaths()) {
                                                log.info("Path to be added:" + path);
                                                path = HTTPUtil.basePath(path, true);
                                                log.info("Path to be added:" + path);
                                                HttpContext httpContext = hs.createContext(path, endPointHandler);
                                                //httpContext.setAuthenticator()
                                            }
                                        }

                                    }
                                    else
                                    {
                                        log.info(ma.method + " has some parameters NOT ANNOTATED");
                                    }
                                }
                            });

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




    private static HTTPEndPoint mergeOuterIntoInner(HTTPEndPoint outer, HTTPEndPoint inner)
    {

        if (outer.getMethods().length > 0)
            inner.setMethods(outer.getMethods());
        if (outer.getPaths().length > 0)
            inner.setPaths(outer.getPaths());
        if (outer.getPermissions().length > 0)
            inner.setPermissions(outer.getPermissions());
        if (outer.getRoles().length > 0)
            inner.setRoles(outer.getRoles());
        if (outer.getAuthenticationTypes().length > 0 )
            inner.setAuthenticationTypes(outer.getAuthenticationTypes());
        if (outer.getRestrictions().length > 0)
            inner.setRestrictions(outer.getRestrictions());

        inner.getProperties().add(outer.getProperties().values(), true);

        return inner;
    }



}
