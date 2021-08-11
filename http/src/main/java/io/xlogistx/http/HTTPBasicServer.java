package io.xlogistx.http;

import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;

import com.sun.net.httpserver.HttpsServer;

import io.xlogistx.common.data.MethodHolder;
import io.xlogistx.common.http.EndPointsManager;
import io.xlogistx.common.http.HTTPServerMapper;
import io.xlogistx.http.handler.BaseEndPointHandler;
import io.xlogistx.http.handler.EndPointHandler;
import io.xlogistx.common.http.EndPointScanner;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LoggerUtil;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.http.HTTPEndPoint;
import org.zoxweb.shared.http.HTTPServerConfig;
import org.zoxweb.shared.http.URIScheme;
import org.zoxweb.shared.net.ConnectionConfig;
import org.zoxweb.shared.net.InetSocketAddressDAO;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.DaemonController;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.SharedUtil;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

public class HTTPBasicServer
  implements DaemonController,
        HTTPServerMapper
{

  private final static Logger log = Logger.getLogger(HTTPBasicServer.class.getName());
  private final HTTPServerConfig config;
  private boolean isClosed = true;
  private final Map<String, HttpServer> servers = new LinkedHashMap<String, HttpServer>();
  public HTTPBasicServer(HTTPServerConfig config)
  {
    SharedUtil.checkIfNulls("HTTPServerConfig null.", config);
    this.config = config;
  }

  public Set<Map.Entry<String, HttpServer>> getHTTPServersMap(){return servers.entrySet();}

  public void start() throws IOException, GeneralSecurityException {
    if (isClosed) {
      if (config != null) {
        isClosed = false;
      }

      ConnectionConfig[] ccs = config.getConnectionConfigs();

      TaskUtil.setMinTaskProcessorThreadCount(config.getThreadPoolSize());
      Executor executor = TaskUtil.getDefaultTaskProcessor();
      if(config.isThreadPoolJavaType())
        executor = Executors.newCachedThreadPool();
      else
        executor = TaskUtil.getDefaultTaskProcessor();

      for(ConnectionConfig cc : ccs)
      {
        String[] schemes = cc.getSchemes();
        for (String scheme : schemes) {
          URIScheme uriScheme = SharedUtil.lookupEnum(scheme, URIScheme.values());
          if (uriScheme != null)
          {
            String serverId = null;
            InetSocketAddressDAO serverAddress = null;
            InetSocketAddress isa = null;
            switch (uriScheme)
            {
              case HTTPS:
                // we need to create an https server
                serverAddress = cc.getSocketConfig();
                serverId = uriScheme.getName() + ":" + serverAddress.getPort();
                isa = new InetSocketAddress(serverAddress.getPort());
                HttpsServer httpsServer = HttpsServer.create(isa, serverAddress.getBacklog());
                NVGenericMap sslConfig = cc.getSSLConfig();
                String ksPassword = sslConfig.getValue("keystore_password");
                String aliasPassword = sslConfig.getValue("alias_password");
                String trustStorePassword = sslConfig.getValue("truststore_password");
                SSLContext sslContext = CryptoUtil.initSSLContext(sslConfig.getValue("keystore_file"),
                        sslConfig.getValue("keystore_type"),
                        ksPassword.toCharArray(),
                        aliasPassword != null ?  aliasPassword.toCharArray() : null,
                        (String)sslConfig.getValue("truststore_file"),
                        trustStorePassword != null ?  trustStorePassword.toCharArray() : null);
                // create the SSLContext

//                List<String> protocols = sslConfig.getValue("protocols");
//                if(protocols != null)
//                {
//                  SSLParameters sslParameters = sslContext.getSupportedSSLParameters();
//                  log.info(Arrays.toString(sslContext.getSupportedSSLParameters().getProtocols()));
//                  sslParameters.setProtocols(protocols.toArray(new String[0]));
//                  log.info(Arrays.toString(sslContext.getSupportedSSLParameters().getProtocols()));
//
//                }

                HttpsConfigurator httpsConfigurator = new HttpsConfigurator(sslContext);

                httpsServer.setHttpsConfigurator(httpsConfigurator);
                httpsServer.setExecutor(executor);
                servers.put(serverId, httpsServer);
                break;
              case HTTP:
                // we need to create an http server
                 serverAddress = cc.getSocketConfig();
                 serverId = uriScheme.getName() + ":" + serverAddress.getPort();
                 isa = new InetSocketAddress(serverAddress.getPort());
                 HttpServer httpServer = HttpServer.create(isa, serverAddress.getBacklog());
                 httpServer.setExecutor(executor);
                 servers.put(serverId, httpServer);
                break;
              case FTP:
              case FILE:
              case MAIL_TO:
              case DATA:
              case WSS:
              case WS:
                break;
            }
          }
        }
      }


      // create end point scanner
      EndPointScanner endPointScanner = new EndPointScanner(config);
      endPointScanner.scan(this);
      Set<Map.Entry<String, HttpServer>>servers = getHTTPServersMap();

      for (Map.Entry<String, HttpServer> server : servers) {
        server.getValue().start();
        log.info(server.getValue().getClass().getName());
      }
    }
  }




  @Override
  public boolean isClosed() {
    return isClosed;
  }

  @Override
  public synchronized void close()
  {
    if(!isClosed())
    {
      isClosed = true;
      servers.values().forEach((s) -> s.stop(5));
    }
  }




  @Override
  public boolean isInstanceNative(Object beanInstance) {
    return beanInstance instanceof BaseEndPointHandler;
  }

  @Override
  public void mapHEP(EndPointsManager endPointsManager, HTTPEndPoint hep, MethodHolder mh, Object beanInstance) {
    EndPointHandler httpHandler;
    if (beanInstance instanceof BaseEndPointHandler)
    {
      httpHandler = (EndPointHandler) beanInstance;
    }
    else
    {
      httpHandler = new EndPointHandler(mh);
    }
    httpHandler.setHTTPEndPoint(hep);

    for (Map.Entry<String, HttpServer> hs : getHTTPServersMap())
    {
      URIScheme serverProtocol = URIScheme.match(hs.getKey());
      for (String path : hep.getPaths())
      {
        // check
        if(hep.getProtocols() != null && hep.getProtocols().length > 0 )
        {
          if(!hep.isProtocolSupported(serverProtocol))
          {
            log.info("Method:" + hep.getName() + "::" +path +" DO NOT supports:" +serverProtocol);
            continue;
          }
        }
        log.info("Method:" + hep.getName() +"::" +path + " supports:" +serverProtocol);
        String pathToBeAdded = HTTPUtil.basePath(path, true);
        HttpContext httpContext = hs.getValue().createContext(pathToBeAdded, httpHandler);
        endPointsManager.map(pathToBeAdded, httpHandler.getHTTPEndPoint(), httpHandler.getMethodHolder());
        log.info(pathToBeAdded  + " [" + httpHandler.ID + "] :" + httpHandler.getHTTPEndPoint());
      }
    }
  }

  public static void main(String... args) {
    long startTS = System.currentTimeMillis();
    try {

      LoggerUtil.enableDefaultLogger("io.xlogistx");
      int index = 0;


      String filename = args[index++];
      log.info("config file:" + filename);
      File file = IOUtil.locateFile(filename);
      HTTPServerConfig hsc = null;

      if(file != null)
        hsc = GSONUtil.fromJSON(IOUtil.inputStreamToString(file), HTTPServerConfig.class);

      log.info("" + hsc);
      log.info("" + Arrays.toString(hsc.getConnectionConfigs()));
      HTTPServerCreator httpServerCreator = new HTTPServerCreator();
      httpServerCreator.setAppConfig(hsc);
      httpServerCreator.createApp();

    } catch (Exception e) {
      e.printStackTrace();
      System.err.println("Usage: HTTPBasicServer server-config.json");
      System.exit(-1);
    }
    startTS = System.currentTimeMillis() - startTS;

    log.info("Start up time:" + Const.TimeInMillis.toString(startTS));

  }
}
