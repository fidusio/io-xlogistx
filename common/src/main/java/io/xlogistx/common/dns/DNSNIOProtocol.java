package io.xlogistx.common.dns;

import org.xbill.DNS.*;
import org.xbill.DNS.Record;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.ProtocolHandler;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.util.RateCounter;

import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;

public class DNSNIOProtocol
        extends ProtocolHandler {
    public static final LogWrapper log = new LogWrapper(ProtocolHandler.class).setEnabled(false);
    private final ByteBuffer buffer = ByteBufferUtil.allocateByteBuffer(512);
    public static final DNSNIOProtocol SINGLETON = new DNSNIOProtocol();
    private final RateCounter rc = new RateCounter("DNSNIOProtocol");


    private DNSNIOProtocol() {
        super(false);
    }

    @Override
    protected void close_internal() throws IOException {

    }

    /**
     * Performs this operation on the given argument.
     *
     * @param selectionKey the input argument
     */
    @Override
    public void accept(SelectionKey selectionKey) {
//        DatagramPacket packet = new DatagramPacket(buf, buf.length);
//        socket.receive(packet);


        SocketAddress clientAddr = null;
        do {
            try {

                buffer.clear();
                clientAddr = ((DatagramChannel) selectionKey.channel()).receive(buffer);
                if (clientAddr != null) {
                    rc.start();
                    buffer.flip();

                    // Get DNS message from received bytes
                    byte[] queryBytes = new byte[buffer.remaining()];
                    buffer.get(queryBytes);

                    Message queryMsg;
                    try {
                        queryMsg = new Message(queryBytes);

                    } catch (IOException ex) {
                        // Ignore invalid DNS messages
                        ex.printStackTrace();
                        continue;
                    }

                    if (log.isEnabled()) log.getLogger().info("query : " + queryMsg.getQuestion());

                    Record question = queryMsg.getQuestion();
                    if (question == null) continue;
                    String qName = question.getName().toString();

                    Message responseMsg = new Message(queryMsg.getHeader().getID());
                    responseMsg.getHeader().setFlag(Flags.QR); // set as response
                    responseMsg.addRecord(question, Section.QUESTION);


                    // Handle locally if in customDomains and Type A query

                    InetAddress cachedHost = DNSRegistrar.SINGLETON.lookup(qName);
                    if (question.getType() == Type.A && cachedHost != null) {
                        responseMsg.addRecord(new ARecord(question.getName(), DClass.IN,60, cachedHost), Section.ANSWER);
                    } else {
                        // Forward to upstream resolver
                        try {
                            responseMsg = DNSRegistrar.SINGLETON.resolve(queryMsg);
                            responseMsg.getHeader().setID(queryMsg.getHeader().getID());
                        } catch (Exception ex) {
                            // If upstream fails, just send empty response
                            // Optionally set RCODE to SERVFAIL
                            responseMsg.getHeader().setRcode(Rcode.SERVFAIL);
                        }
                    }

                    // Send response
                    byte[] respBytes = responseMsg.toWire(512);
                    ByteBuffer respBuffer = ByteBuffer.wrap(respBytes);
                    SocketAddress destination = clientAddr;
                    ((DatagramChannel) selectionKey.channel()).send(respBuffer, destination);
//                    TaskUtil.defaultTaskScheduler().execute(() -> {
//                        try {
//                            ((DatagramChannel) selectionKey.channel()).send(respBuffer, destination);
//                        } catch (IOException e) {
//                            e.printStackTrace();
//                        }
//                    });


                }
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                rc.stop();
            }
        } while (clientAddr != null);
        if (log.isEnabled()) log.getLogger().info("rate-counter: " + rc);
        if (log.isEnabled()) log.getLogger().info("threadinfo: " + GSONUtil.toJSONDefault(TaskUtil.info()));
    }


    /**
     * Returns the property description.
     *
     * @return description
     */
    @Override
    public String getDescription() {
        return "";
    }

    /**
     * @return the name of the object
     */
    @Override
    public String getName() {
        return "";
    }
}
