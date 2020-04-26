package io.xlogistx.http;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import io.xlogistx.http.handler.EndPointScanner;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.http.HTTPServerConfig;
import org.zoxweb.shared.http.URIScheme;
import org.zoxweb.shared.net.ConnectionConfig;
import org.zoxweb.shared.net.InetSocketAddressDAO;
import org.zoxweb.shared.util.DaemonController;
import org.zoxweb.shared.util.SharedUtil;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.IOException;

import java.net.InetSocketAddress;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Logger;

public class HTTPBasicServer
  implements DaemonController
{
//  static class ContextHandler implements HttpHandler {
//
//    public void handle(HttpExchange he) throws IOException {
//      InputStream is = he.getRequestBody();
//      is.close();
//      NVGenericMap nvgm = new NVGenericMap();
//      nvgm.add("context", he.getHttpContext().getPath());
//      String json = GSONUtil.DEFAULT_GSON.toJson(nvgm);
//      byte[] response = SharedStringUtil.getBytes(json);
//      he.getResponseHeaders()
//              .add(HTTPHeaderName.CONTENT_TYPE.getName(), HTTPMimeType.APPLICATION_JSON.getValue());
//      he.getResponseHeaders().add(HTTPHeaderName.CONTENT_TYPE.getName(), "charset=utf-8");
//      he.sendResponseHeaders(200, response.length);
//      OutputStream os = he.getResponseBody();
//      os.write(response);
//      os.close();
//    }
//  }


  private final static Logger log = Logger.getLogger(HTTPBasicServer.class.getName());
  private HTTPServerConfig config;
  private boolean isClosed = true;
  private Map<String, HttpServer> servers = new LinkedHashMap<String, HttpServer>();

  public HTTPBasicServer(HTTPServerConfig config)
  {
    this.config = config;
  }



  public void start() throws IOException {
    if (isClosed) {
      if (config != null) {
        isClosed = false;
      }

      ConnectionConfig[] ccs = config.getConnectionConfigs();

      TaskUtil.setMinTaskProcessorThreadCount(config.getThreadPoolSize());
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
                SSLContext sslContext = null;
                // create the SSLContext
                HttpsConfigurator httpsConfigurator = new HttpsConfigurator(sslContext);
                httpsServer.setHttpsConfigurator(httpsConfigurator);
                httpsServer.setExecutor(TaskUtil.getDefaultTaskProcessor());
                servers.put(serverId, httpsServer);
                break;
              case HTTP:
                // we need to create an http server
                 serverAddress = cc.getSocketConfig();
                 serverId = uriScheme.getName() + ":" + serverAddress.getPort();
                 isa = new InetSocketAddress(serverAddress.getPort());
                 HttpServer httpServer = HttpServer.create(isa, serverAddress.getBacklog());
                 httpServer.setExecutor(TaskUtil.getDefaultTaskProcessor());
                 servers.put(serverId, httpServer);
                break;
              case FTP:
                break;
              case FILE:
                break;
              case MAIL_TO:
                break;
              case DATA:
                break;
              case WSS:
                break;
              case WS:
                break;
            }
          }
        }

        // create end point scanner
        EndPointScanner endPointScanner = new EndPointScanner(config, this);
        endPointScanner.scan();
      }
    }
  }




  @Override
  public boolean isClosed() {
    return isClosed;
  }

  @Override
  public synchronized void close() throws IOException {

    if(!isClosed()) {

      isClosed = true;
    }
  }


  public static void main(String... args) {
    try {
      int index = 0;


      String filename = args[index++];
      File file = IOUtil.locateFile(filename);
      HTTPServerConfig hsc = null;

      if(file != null)
        hsc = GSONUtil.fromJSON(IOUtil.inputStreamToString(file), HTTPServerConfig.class);

      log.info("" + hsc);
      log.info("" + hsc.getConnectionConfigs());

//      int port = Integer.parseInt(args[index++]);
//      HttpServer server = HttpServer.create(new InetSocketAddress(port), 250);
//      String baseFolder = args[index++];
//      for (; index < args.length; index++) {
//        server.createContext("/" + args[index], new ContextHandler());
//      }
//      HttpContext hc = server.createContext("/.well-known/pki-validation/", new FileHandler("/public"));
//      hc.setAuthenticator(new Authenticator() {
//        @Override
//        public Result authenticate(HttpExchange httpExchange) {
//          return null;
//        }
//      });
//      server.createContext("/toto", new FileHandler());
//      server.setExecutor(TaskUtil.getDefaultTaskProcessor());
//
//      HttpContext hc = server.createContext("/", new HTTPFileHandler(baseFolder));
//
//      log.info(hc.getPath());
//      server.start();
//
//      log.info("server started @ " + server.getAddress());
    } catch (Exception e) {
      e.printStackTrace();
      System.err.println("Usage: HTTPBasicServer server-config.json");
    }
  }
}
