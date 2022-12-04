package io.xlogistx.common.http;


import io.xlogistx.common.data.MethodHolder;

import org.zoxweb.server.util.ReflectionUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.http.HTTPEndPoint;
import org.zoxweb.shared.http.HTTPServerConfig;


import org.zoxweb.shared.util.SetNVProperties;

import java.lang.reflect.Method;



import java.util.logging.Logger;

public class EndPointScanner
{

    private static final Logger log = Logger.getLogger(EndPointScanner.class.getName());
    private final HTTPServerConfig serverConfig;
    private final EndPointsManager endPointsManager = new EndPointsManager();

    public EndPointScanner(HTTPServerConfig serverConfig)
    {
        this.serverConfig = serverConfig;

    }


//    public EndPointsManager getEndPointsManager()
//    {
//        return endPointsManager;
//    }

    public EndPointsManager scan(HTTPServerMapper serverMapper)
    {
        HTTPEndPoint[]allHEP = serverConfig.getEndPoints();
        for(HTTPEndPoint configHEP : allHEP)
        {

            // annotation override
            // If there is a conflict with annotation
            // the json config file will override the code defined one
            // this technique will allow configuration to update on the fly without the
            // need to recompile the code
            try
            {
                String beanName = configHEP.getBean();
                Class<?> beanClass = Class.forName(beanName);
                log.info("Bean to be create:" + beanName);
                Object beanInstance = ReflectionUtil.createBean(beanClass);
                log.info("bean:" + beanName + " " + beanInstance + " " + allHEP.length);
                //BaseEndPointHandler beph = null;
                if(beanInstance instanceof SetNVProperties)
                {
                    ((SetNVProperties) beanInstance).setProperties(configHEP.getProperties());
                }

                log.info("bean:" + beanName);
                if (serverMapper.isInstanceNative(beanInstance))
                {
                    // we just create the context
                    //
//                    beph = (BaseEndPointHandler) beanInstance;
//                    beph.setHTTPEndPoint(configHEP);
                    serverMapper.mapHEP(endPointsManager, configHEP, null, beanInstance);
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
                            classHEP = EndPointsManager.scanAnnotations(serverConfig.getBaseURI(), classHEP, classAnnotationMap.getClassAnnotations(), false);
                            classHEP = EndPointsManager.mergeOuterIntoInner(configHEP, classHEP, false);

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
                                    if (EndPointsManager.areAllParametersUniquelyAnnotatedParamProp(methodAnnotations))
                                    {

                                        HTTPEndPoint methodHEP = EndPointsManager.scanAnnotations(serverConfig.getBaseURI(),
                                                new HTTPEndPoint(),
                                                methodAnnotations.methodAnnotations,
                                                true);

                                        methodHEP = EndPointsManager.mergeOuterIntoInner(classHEP, methodHEP, false);

//                                        EndPointHandler endPointHandler = new EndPointHandler(new MethodHolder(beanInstance, methodAnnotations));
//                                        endPointHandler.setHTTPEndPoint(methodHEP);

                                        serverMapper.mapHEP(endPointsManager, methodHEP, new MethodHolder(beanInstance, methodAnnotations), beanInstance);

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


        return endPointsManager;
    }


//    private void mapHEP(HTTPBasicServer server, HTTPEndPoint hep, MethodHolder mh, Object beanInstance)
//    {
//
//        EndPointHandler httpHandler;
//        if (beanInstance instanceof BaseEndPointHandler)
//        {
//            httpHandler = (EndPointHandler) beanInstance;
//        }
//        else
//        {
//            httpHandler = new EndPointHandler(mh);
//        }
//        httpHandler.setHTTPEndPoint(hep);
//
//        for (Map.Entry<String, HttpServer> hs : server.getHTTPServersMap())
//        {
//            URIScheme serverProtocol = URIScheme.match(hs.getKey());
//            for (String path : hep.getPaths())
//            {
//                // check
//                if(hep.getProtocols() != null && hep.getProtocols().length > 0 )
//                {
//                    if(!hep.isProtocolSupported(serverProtocol))
//                    {
//                        log.info("Method:" + hep.getName() + "::" +path +" DO NOT supports:" +serverProtocol);
//                        continue;
//                    }
//                }
//                log.info("Method:" + hep.getName() +"::" +path + " supports:" +serverProtocol);
//                String pathToBeAdded = HTTPUtil.basePath(path, true);
//                HttpContext httpContext = hs.getValue().createContext(pathToBeAdded, httpHandler);
//                endPointsManager.map(pathToBeAdded, httpHandler.getHTTPEndPoint(), httpHandler.getMethodHolder());
//                log.info(pathToBeAdded  + " [" + httpHandler.ID + "] :" + httpHandler.getHTTPEndPoint());
//            }
//        }
//    }






}
