package io.xlogistx.http;

import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.http.HTTPServerConfig;
import org.zoxweb.shared.util.DaemonController;
import java.io.File;
import java.io.IOException;

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
  private boolean isClosed = false;

  public HTTPBasicServer(HTTPServerConfig config)
  {
    this.config = config;
  }

  public void start()
  {
    if (config != null)
    {
      isClosed = false;
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
