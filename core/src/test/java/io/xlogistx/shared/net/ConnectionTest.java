package io.xlogistx.shared.net;

import org.zoxweb.server.io.IOUtil;
import org.zoxweb.shared.net.IPAddress;

import java.net.Socket;

public class ConnectionTest {

    public static void main(String ...args)
    {
        try
        {
            int index = 0;
            IPAddress address = new IPAddress(args[index++]);
            System.out.println("Connecting to " + address);
            Socket socket = new Socket(address.getInetAddress(), address.getPort());


            socket.getInputStream();

            IOUtil.close(socket);

        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }
}
