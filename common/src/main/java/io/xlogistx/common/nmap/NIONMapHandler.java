package io.xlogistx.common.nmap;

import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.net.ProtocolHandler;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;

public class NIONMapHandler extends ProtocolHandler {

    private ByteBuffer bb = ByteBufferUtil.allocateByteBuffer(512);
    @Override
    public void close() throws IOException {

        IOUtil.close(phSChannel);
    }

    @Override
    public void accept(SelectionKey key)
    {
        if (phSK == null)
        {
            phSK = key;
        }

        try
        {
            if (key.isConnectable())
            {
                if (((SocketChannel) key.channel()).isConnectionPending()) {

                    if (((SocketChannel) key.channel()).finishConnect())
                        System.out.println("finished connecting to :" +  ((SocketChannel) key.channel()).getRemoteAddress());

                }
//                if (((SocketChannel) key.channel()).isConnected()) {
//                    System.out.println("connected : " + ((SocketChannel) key.channel()).getRemoteAddress() + " open");
//                }

            }
            else if (key.isReadable())
            {
                int read = ((SocketChannel) key.channel()).read(bb);
                System.out.println("bytes read: " + read);
            }
            else
            {
                System.out.println("not connecting to :" +  ((SocketChannel) key.channel()).getRemoteAddress());
            }
            close();
        }
        catch (Exception e)
        {
            e.printStackTrace();
            IOUtil.close(this);
        }

    }

    @Override
    public String getDescription() {
        return null;
    }

    @Override
    public String getName() {
        return null;
    }
//    public void setupConnection(AbstractSelectableChannel asc, boolean isBlocking) throws IOException
//    {
//        phSChannel = (SocketChannel) asc;
//    }
}
