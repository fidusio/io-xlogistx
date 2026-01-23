package io.xlogistx.common.net;

import io.xlogistx.common.dns.DNSRegistrar;
import io.xlogistx.common.dns.DNSUDPNIOCallback;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.task.TaskUtil;

public class DNSTester {
    public static void main(String[] args) {
        try {
            DNSUDPNIOCallback.log.setEnabled(true);
            NIOSocket nioSocket = new NIOSocket(TaskUtil.defaultTaskProcessor(), TaskUtil.defaultTaskScheduler());
            DNSRegistrar.SINGLETON.setResolver("10.0.0.1");
            DNSUDPNIOCallback dnsUDPNIOCallback = new DNSUDPNIOCallback(53);
            nioSocket.addDatagramSocket(dnsUDPNIOCallback);
            System.out.println("waiting for dns queries");
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
}
