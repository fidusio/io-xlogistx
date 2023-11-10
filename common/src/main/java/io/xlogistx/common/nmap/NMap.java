package io.xlogistx.common.nmap;

import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.data.Range;
import org.zoxweb.shared.util.Const;

import java.net.InetSocketAddress;

public class NMap {

    public static void main (String ...args)
    {
        try
        {

            int index = 0;
            String host = args[index++];
            Range<Integer> ports = Range.toRange(args[index++]);

            NIOSocket nioSocket = new NIOSocket(TaskUtil.defaultTaskProcessor(), TaskUtil.defaultTaskScheduler());
            NIONMapProtocolFactory nmapPF = new NIONMapProtocolFactory();
            long ts = System.currentTimeMillis();
            for (int i = ports.getLoopStart(); i < ports.getLoopEnd(); i++)
            {
                InetSocketAddress sa = new InetSocketAddress(host, i);
                //System.out.println("Scanning: " + sa);

                nioSocket.addClientSocket(sa, nmapPF);
                System.out.println("Scanning: " + sa);
            }
            //NIOSocket.logger.setEnabled(true);
            System.out.println(GSONUtil.toJSONDefault(nioSocket.getStats(), true) );

            ts = TaskUtil.waitIfBusy(50) - ts;
            System.out.println("it took " + Const.TimeInMillis.toString(ts));

            TaskUtil.sleep(Const.TimeInMillis.SECOND.MILLIS*20);
            System.out.println(GSONUtil.toJSONDefault(nioSocket.getStats(), true) );
            TaskUtil.waitIfBusyThenClose(50);


            nioSocket.close();




        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }
}
