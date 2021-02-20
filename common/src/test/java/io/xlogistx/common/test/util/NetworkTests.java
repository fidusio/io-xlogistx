package io.xlogistx.common.test.util;

import org.junit.jupiter.api.Test;
import org.zoxweb.server.net.NetUtil;

import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;

public class NetworkTests
{
    @Test
    public void interfacesList() throws IOException {
       Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
       while(interfaces.hasMoreElements())
       {
           NetworkInterface ni = interfaces.nextElement();
           System.out.println("name: " + ni.getName() + " display name: " + ni.getDisplayName());
           InetAddress ia = NetUtil.getIPV4MainAddress(ni);
           if(ia != null)
           {
               System.out.println("main ip address: " + ia.getHostAddress() + "," + ia.getCanonicalHostName() + "," + ia.getHostName());
           }
       }
    }
}
