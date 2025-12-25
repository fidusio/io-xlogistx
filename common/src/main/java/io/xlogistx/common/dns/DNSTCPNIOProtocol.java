package io.xlogistx.common.dns;

import org.xbill.DNS.*;
import org.xbill.DNS.Record;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.ProtocolHandler;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;

/**
 * DNS protocol handler for TCP connections.
 * Unlike UDP, TCP DNS messages are prefixed with a 2-byte length field.
 */
public class DNSTCPNIOProtocol extends ProtocolHandler {
    public static final int DNS_BUFFER_SIZE = 65535; // TCP DNS can be larger than UDP
    public static final LogWrapper log = new LogWrapper(DNSTCPNIOProtocol.class).setEnabled(false);

    private final ByteBuffer lengthBuffer = ByteBuffer.allocate(2);
    private ByteBuffer messageBuffer = null;
//    private SocketChannel clientChannel;

    public DNSTCPNIOProtocol() {
        super(true);
    }

    @Override
    protected void close_internal() throws IOException {
        IOUtil.close(phSChannel);
        if (phSK != null) {
            getSelectorController().cancelSelectionKey(phSK);
        }
    }

    @Override
    public void accept(SelectionKey selectionKey) {
        phSChannel = (SocketChannel) selectionKey.channel();
        phSK = selectionKey;

        try {


            // Step 1: Read the 2-byte length prefix if not yet read
            if (messageBuffer == null) {
                int bytesRead = phSChannel.read(lengthBuffer);
                if (bytesRead == -1) {
                    close();
                    return;
                }

                if (lengthBuffer.hasRemaining()) {
                    return; // Wait for more data
                }

                lengthBuffer.flip();
                int messageLength = ((lengthBuffer.get() & 0xFF) << 8) | (lengthBuffer.get() & 0xFF);
                messageBuffer = ByteBuffer.allocate(messageLength);
                lengthBuffer.clear();
            }

            // Step 2: Read the DNS message
            int bytesRead = phSChannel.read(messageBuffer);
            if (bytesRead == -1) {
                close();
                return;
            }

            if (messageBuffer.hasRemaining()) {
                return; // Wait for more data
            }

            // Step 3: Process the complete message
            messageBuffer.flip();

            byte[] data = new byte[messageBuffer.remaining()];
            messageBuffer.get(data);
            messageBuffer = null; // Reset for next message

            processAndRespond(data, phSChannel);

        } catch (IOException e) {
            if (log.isEnabled()) log.getLogger().info("Error processing TCP DNS request: " + e.getMessage());
            IOUtil.close(this);
        }
    }



    private void processAndRespond(byte[] data, SocketChannel channel) throws IOException {
        try {
            Message queryMsg = new Message(data);
            Record question = queryMsg.getQuestion();

            if (question == null) {
                return;
            }

            if (log.isEnabled()) log.getLogger().info("TCP query: " + question);

            Message responseMsg = new Message(queryMsg.getHeader().getID());
            responseMsg.getHeader().setFlag(Flags.QR);
            responseMsg.addRecord(question, Section.QUESTION);

            String qName = question.getName().toString();
            InetAddress cachedHost = DNSRegistrar.SINGLETON.lookup(qName);

            if (question.getType() == Type.A && cachedHost != null) {
                responseMsg.addRecord(new ARecord(question.getName(), DClass.IN, 60, cachedHost), Section.ANSWER);
            } else {
                try {
                    responseMsg = DNSRegistrar.SINGLETON.resolve(queryMsg);
                    responseMsg.getHeader().setID(queryMsg.getHeader().getID());
                } catch (Exception ex) {
                    responseMsg.getHeader().setRcode(Rcode.SERVFAIL);
                }
            }

            // Send TCP response with 2-byte length prefix
            byte[] responseData = responseMsg.toWire();
            ByteBuffer response = ByteBuffer.allocate(2 + responseData.length);
            response.putShort((short) responseData.length);
            response.put(responseData);
            response.flip();


            while (response.hasRemaining()) {
                channel.write(response);

            }

            if (log.isEnabled()) log.getLogger().info("TCP response sent, size: " + responseData.length);

        } finally {
            ByteBufferUtil.cache(data);
        }
    }

    /**
     * Setup the connection for this protocol handler.
     * Call this after accepting a new TCP connection.
     *
     * @param channel the accepted SocketChannel
     * @throws IOException if registration fails
     */
    protected void setupConnection(SocketChannel channel) throws IOException {
        this.phSChannel = channel;
        getSelectorController().register(channel, SelectionKey.OP_READ, this, false);
    }

    @Override
    public String getDescription() {
        return "Java DNS TCP cache";
    }

    @Override
    public String getName() {
        return "DNSTCPNIOProtocol";
    }
}