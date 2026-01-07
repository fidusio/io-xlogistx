package io.xlogistx.http;

import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.task.ConsumerCallback;
import org.zoxweb.shared.util.Const;

import java.io.IOException;
import java.nio.channels.SocketChannel;
import java.util.concurrent.atomic.AtomicLong;

public class NIOHTTPServerTest {
    static class ConnectionTracker
            implements ConsumerCallback<SocketChannel> {
        AtomicLong successCount = new AtomicLong(0);
        AtomicLong failCount = new AtomicLong(0);

        /**
         * Performs this operation on the given argument.
         *
         * @param channel the input argument
         */
        @Override
        public void accept(SocketChannel channel) {
            successCount.incrementAndGet();
            try {
                System.out.println(channel.getRemoteAddress() + " " + channel.isConnected() + " total: " + total());
            } catch (IOException e) {
                e.printStackTrace();
            } finally {

                try {


                    long ts = Const.TimeInMillis.SECOND.MILLIS * (total() % 100);
                    System.out.println(Const.TimeInMillis.toString(ts) + " " + channel.isConnected() + " tot: " + total());
                    TaskUtil.defaultTaskScheduler().queue(ts, () ->
                    {System.out.println("Closing " + channel);
                            IOUtil.close(channel);});
                }
                catch (Exception e) { e.printStackTrace(); }
            }
        }

        /**
         *
         * @param e
         */
        @Override
        public void exception(Exception e) {
            //e.printStackTrace();
            failCount.incrementAndGet();
            //System.err.println(e +" " + total());
        }

        public String toString() {
            return successCount.toString() + ", " + failCount.toString();
        }

        public long total() {
            return successCount.get() + failCount.get();
        }
    }


    public static void main(String[] args) {
        NIOHTTPServer.main(args);

//        NIOHTTPServer niohttpServer = ResourceManager.SINGLETON.lookup(ResourceManager.Resource.HTTP_SERVER);
//        if (niohttpServer != null) {
//            NIOSocket nioSocket = niohttpServer.getNIOSocket();
//            TaskUtil.sleep(Const.TimeInMillis.SECOND.mult(10));
//
//            long ts = System.currentTimeMillis();
//            IPAddress[] ipAddresses = IPAddress.parseRange("xlogistx.io:(0,1024]");
//            ConnectionTracker connectionTracker = new ConnectionTracker();
//
//            try {
//
//
//                for (IPAddress ipAddress : ipAddresses) {
//                    //System.out.println(ipAddress);
//                    nioSocket.addClientSocket(new InetSocketAddress(ipAddress.getInetAddress(), ipAddress.getPort()), 10, connectionTracker);
//                }
//
//                TaskUtil.waitIfBusy(500, () -> connectionTracker.total() == ipAddresses.length);
//                System.out.println(GSONUtil.toJSONDefault(TaskUtil.info()));
//                System.out.println(connectionTracker + " it took " + Const.TimeInMillis.toString(System.currentTimeMillis() - ts));
//            }
//            catch (Exception e) {
//                e.printStackTrace();
//            }
//        }
    }
}
