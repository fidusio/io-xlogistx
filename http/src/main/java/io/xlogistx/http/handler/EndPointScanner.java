package io.xlogistx.http.handler;

import com.sun.net.httpserver.HttpHandler;
import io.xlogistx.http.HTTPBasicServer;
import org.zoxweb.shared.http.HTTPEndPoint;
import org.zoxweb.shared.http.HTTPServerConfig;

public class EndPointScanner
{
    private final HTTPServerConfig serverConfig;
    private final HTTPBasicServer server;

    public EndPointScanner(HTTPServerConfig serverConfig, HTTPBasicServer server)
    {
        this.serverConfig = serverConfig;
        this.server = server;
    }


    public void scan()
    {
        for(HTTPEndPoint hep : serverConfig.getEndPoints())
        {

            // annotation override
            // If there is a conflict with annotation
            // the json config file will override the code defined one
            // this technique will allow configuration to updated on the fly without the
            // need to recompile the code
            try
            {
                String beanName = hep.getBean();
                Class<?> beanClass = Class.forName(beanName);
                Object bean = beanClass.getDeclaredConstructor().newInstance();

                if (bean instanceof HttpHandler)
                {
                    // we just create the context

                    //
                }
                else
                {

                }
            }
            catch(Exception e)
            {
                e.printStackTrace();
            }
        }
    }






}
