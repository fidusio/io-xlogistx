package io.xlogistx.http;

import org.zoxweb.server.http.OkHTTPCall;
import org.zoxweb.shared.http.HTTPAuthorizationBasic;
import org.zoxweb.shared.http.HTTPMessageConfig;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;

public class WebLoginTest {
     public static void main(String[] args) {
         try
         {
             int index = 0;
             String url = args[index++];
             String username = args[index++];
             String password = args[index++];
             HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, null, "get");
             hmci.setAuthorization(new HTTPAuthorizationBasic(username, password));
             hmci.setSecureCheckEnabled(false);
             System.out.println(url + " login user " + username);
             System.out.println(OkHTTPCall.send(hmci));
         }
         catch (Exception e)
         {
             System.err.println("usage: java WebLoginTest <url> <username> <password>");
             e.printStackTrace();
         }
     }
}
