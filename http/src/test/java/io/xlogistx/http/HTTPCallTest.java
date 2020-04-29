package io.xlogistx.http;

import org.zoxweb.server.http.HTTPCall;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.http.HTTPMessageConfig;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPResponseData;
import org.zoxweb.shared.util.Const;

import java.io.IOException;

public class HTTPCallTest {
    public static void main(String ...args)
    {
        try
        {
            int index = 0;
            String url = args[index++];
            int count = Integer.parseInt(args[index++]);
            String user = args.length > index ? args[index++] : null;
            String password = args.length > index ? args[index++] : null;
            HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, null, HTTPMethod.GET, false);
            hmci.setUser(user);
            hmci.setPassword(password);
            new HTTPCall(hmci).sendRequest();
            long ts = System.currentTimeMillis();
            for(int i = 0; i < count; i++)
            {

                TaskUtil.getDefaultTaskProcessor().execute(new Runnable() {
                    @Override
                    public void run() {
                        HTTPCall hc = new HTTPCall(hmci);
                        try {
                            HTTPResponseData hrd = hc.sendRequest();
                            //System.out.println(hrd);
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                });

            }

            ts = TaskUtil.waitIfBusyThenClose(20)- ts;
            System.out.println(Const.TimeInMillis.toString(ts) + " rate:" + ((float)count/(float)ts)*Const.TimeInMillis.SECOND.MILLIS);
        }
        catch(Exception e)
        {
            e.printStackTrace();
            System.err.println("Usage: url count");
        }
    }
}
