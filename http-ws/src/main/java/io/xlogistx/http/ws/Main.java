package io.xlogistx.http.ws;


import io.xlogistx.http.HTTPBasicServer;
import io.xlogistx.http.HTTPServerCreator;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LoggerUtil;
import org.zoxweb.server.net.NIOConfig;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.net.security.IPBlockerListener;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.data.ConfigDAO;
import org.zoxweb.shared.http.HTTPServerConfig;
import org.zoxweb.shared.security.IPBlockerConfig;
import org.zoxweb.shared.util.*;

import java.io.File;
import java.util.List;
import java.util.logging.Logger;

public class Main {
    private final static Logger log = Logger.getLogger(Main.class.getName());
    public enum Param
        implements SetNameValue<Object>
    {
        WS(HTTPServerCreator.RESOURCE_NAME),
        NI_CONFIG(NIOConfig.RESOURCE_NAME),
        IP_BLOCKER(IPBlockerListener.RESOURCE_NAME),
        ;
        private String name;
        private Object val;

        Param(String name)
        {
            this.name = name;
        }
        @Override
        public String getName() {
            return name;
        }

        @Override
        public void setValue(Object value) {
            val = value;
        }

        @Override
        public Object getValue() {
            return val;
        }

        @Override
        public void setName(String name) {

        }
    }

    public static void main(String ...args)
    {
        try
        {
            LoggerUtil.enableDefaultLogger("io.xlogistx");
            List<GetNameValue<String>> parameters = SharedStringUtil.parseStrings('=', args);
            HTTPBasicServer ws = null;
            NIOSocket nioSocket = null;
            IPBlockerListener ipBlocker = null;


            for(GetNameValue<String> gnvs : parameters)
            {
                Param p = SharedUtil.lookupEnum(gnvs.getName(), Param.values());
                if(p != null)
                {
                    switch (p)
                    {

                        case WS:
                            File file = IOUtil.locateFile(gnvs.getValue());
                            HTTPServerConfig hsc = null;
                            hsc = GSONUtil.fromJSON(IOUtil.inputStreamToString(file), HTTPServerConfig.class);
                            log.info("" + hsc);
                            log.info("" + hsc.getConnectionConfigs());
                            HTTPServerCreator httpServerCreator = new HTTPServerCreator();
                            httpServerCreator.setAppConfig(hsc);
                            ws = httpServerCreator.createApp();
                            p.setValue(ws);
                            break;
                        case NI_CONFIG:
                            ConfigDAO configDAO = GSONUtil.fromJSON(IOUtil.inputStreamToString(gnvs.getValue()));
                            System.out.println(GSONUtil.toJSON(configDAO, true, false, false));
                            NIOConfig nioConfig = new NIOConfig(configDAO);
                            nioSocket = nioConfig.createApp();
                            nioSocket.setEventManager(TaskUtil.getDefaultEventManager());
                            p.setValue(nioSocket);
                            break;
                        case IP_BLOCKER:
                            IPBlockerConfig ipBlockerConfig = GSONUtil.fromJSON(IOUtil.inputStreamToString(gnvs.getValue()), IPBlockerConfig.class);
                            IPBlockerListener.Creator c = new IPBlockerListener.Creator();
                            c.setAppConfig(ipBlockerConfig);
                            ipBlocker = c.createApp();
                            p.setValue(ipBlocker);
                            break;
                    }
                }
            }

            Object lastApp = null;
            StringBuilder message = new StringBuilder();
            for(Param p : Param.values())
            {
                if(p.getValue() != null) {
                    message.append(" " + p.getName());
                    lastApp = p.getValue();
                }


            }

            if (lastApp == null)
            {
                throw new IllegalArgumentException(parameters + " Invalid configuration");
            }

            log.info("App Started:" + message.toString());

        }
        catch(Exception e)
        {
            e.printStackTrace();
            System.err.println("usage: [" + Param.WS.getName()+"=wsonfig.json] [" +Param.NI_CONFIG.getName() +"=niconfig.json] [" +Param.IP_BLOCKER.getName() +"=ipbconfig.json]");
            System.exit(-1);
        }
    }
}
