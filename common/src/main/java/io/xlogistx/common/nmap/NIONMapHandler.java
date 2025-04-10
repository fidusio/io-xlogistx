package io.xlogistx.common.nmap;

import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.ProtocolHandler;

import java.io.IOException;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.AbstractSelectableChannel;

public class NIONMapHandler extends ProtocolHandler {
    public final static LogWrapper logger = new LogWrapper(ProtocolHandler.class).setEnabled(false);
    private ByteBuffer bb = ByteBufferUtil.allocateByteBuffer(512);
    @Override
    protected void  close_internal() throws IOException {

        IOUtil.close(phSChannel);
        getSelectorController().cancelSelectionKey(phSK);
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
                if (((SocketChannel) key.channel()).isConnectionPending())
                {

                    if (((SocketChannel) key.channel()).finishConnect())
                        System.out.println("finished connecting to :" +  ((SocketChannel) key.channel()).getRemoteAddress());

                }

            }
            else if (key.isReadable())
            {

                ((Buffer) bb).clear();
                int read = phSChannel.isConnected()? phSChannel.read(bb) : -1;
                if (read == -1)
                    close();
            }

            close();
        }
        catch (Exception e)
        {
            if(logger.isEnabled())
                System.err.println(e);
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


    public void setupConnection(AbstractSelectableChannel asc, boolean isBlocking) throws IOException
    {
        phSChannel = (SocketChannel) asc;


        SelectionKey sk = getSelectorController().channelSelectionKey(asc);
        if(logger.isEnabled()) logger.getLogger().info("Selection key : " + sk);

        if (sk != null)
            getSelectorController().update(sk, sk.interestOps() | SelectionKey.OP_READ, this);
        else
            getSelectorController().register(phSChannel, SelectionKey.OP_READ, this, isBlocking);
    }
//    public void setupConnection(AbstractSelectableChannel asc, boolean isBlocking) throws IOException
//    {
//        phSChannel = (SocketChannel) asc;
//    }
}
