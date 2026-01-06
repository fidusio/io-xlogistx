package io.xlogistx.common.nio;

import org.zoxweb.shared.net.IPAddress;
import org.zoxweb.shared.task.ConsumerCallback;
import org.zoxweb.shared.util.NotFoundException;
import org.zoxweb.shared.util.SUS;

import java.net.InetSocketAddress;
import java.nio.channels.SocketChannel;

public class NIOAsyncSocketChannel
        implements ConsumerCallback<SocketChannel> {

    private volatile SocketChannel socketChannel = null;
    private volatile Exception error = null;
    private final IPAddress address;

    public NIOAsyncSocketChannel(IPAddress address) {
        SUS.checkIfNull("Null ip address", address);
        this.address = address;
    }

    /**
     * Performs this operation on the given argument.
     *
     * @param channel the input argument
     */
    @Override
    public void accept(SocketChannel channel) {
        socketChannel = channel;
    }

    public IPAddress ipAddress() {
        return address;
    }

    public InetSocketAddress inetSocketAddress() {
        return new InetSocketAddress(address.getInetAddress(), address.getPort());
    }

    public SocketChannel socketChannel()
            throws NotFoundException {
        if (socketChannel == null)
            throw new NotFoundException("SocketChannel for " + address + " not available yet.");
        return socketChannel;
    }

    public Exception exception() {
        return error;
    }

    @Override
    public void exception(Exception e) {
        error = e;
    }
}
