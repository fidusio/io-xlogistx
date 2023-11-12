package io.xlogistx.common.nmap;

import org.zoxweb.server.net.NIOChannelMonitor;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.data.Range;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.ParamUtil;

import java.net.InetSocketAddress;

public class NMap {

    public static void main (String ...args)
    {
        try
        {
            ParamUtil.ParamMap params = ParamUtil.parse("=", args);
            String host = params.stringValue("host", false);
            String range = params.stringValue("range", true);
            Range<Integer> ports = range != null ? Range.toRange(range) :Range.toRange("[10, 1024]");
            boolean statLogs = params.booleanValue("logs", true);

            int timeoutInSec = params.intValue("timeout", 5);
            NIOChannelMonitor.logger.setEnabled(statLogs);
            NIONMapHandler.logger.setEnabled(statLogs);

            NIOSocket nioSocket = new NIOSocket(TaskUtil.defaultTaskProcessor(), TaskUtil.defaultTaskScheduler());
            NIONMapProtocolFactory nmapPF = new NIONMapProtocolFactory();
            long ts = System.currentTimeMillis();
            for (int i = ports.getLoopStart(); i < ports.getLoopEnd(); i++)
            {
                InetSocketAddress sa = new InetSocketAddress(host, i);
                //System.out.println("Scanning: " + sa);

                nioSocket.addClientSocket(sa, nmapPF, timeoutInSec, null);
                //System.out.println("Scanning: " + sa);
            }
            //NIOSocket.logger.setEnabled(true);
            System.out.println(GSONUtil.toJSONDefault(nioSocket.getStats(), true) );

            ts = TaskUtil.waitIfBusy(50) - ts;
            System.out.println("it took " + Const.TimeInMillis.toString(ts));

            TaskUtil.sleep(Const.TimeInMillis.SECOND.mult(timeoutInSec + 3));
            System.out.println(GSONUtil.toJSONDefault(nioSocket.getStats(), true) );
            TaskUtil.waitIfBusyThenClose(50);
            System.out.println("after waitIfBusyThenClose");

            nioSocket.close();
            System.out.println("after nioSocket.close()");
            TaskUtil.close();




        }
        catch (Exception e)
        {
            e.printStackTrace();
            System.err.println("Usage: host=ip/hostname [range=[80, 443], default [10,1024] [timeout=5(in secs), default 5] [logs=true, default false]" );
        }
    }
}
