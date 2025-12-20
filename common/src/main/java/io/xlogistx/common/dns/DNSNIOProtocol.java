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
import java.util.concurrent.Executor;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class DNSNIOProtocol
        extends ProtocolHandler {
    public static final int DNS_BUFFER_SIZE = 4096;
    public static final LogWrapper log = new LogWrapper(ProtocolHandler.class).setEnabled(false);
    private final ByteBuffer buffer = ByteBufferUtil.allocateByteBuffer(DNS_BUFFER_SIZE);
    private final RateCounter rc = new RateCounter("DNSNIOProtocol");


    private final Executor localExecutor;
    private final Lock localLock = new ReentrantLock();


    public DNSNIOProtocol(Executor localExecutor) {
        super(false);
        this.localExecutor = localExecutor;
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
        SocketAddress clientAddr = null;
        DatagramChannel channel = (DatagramChannel) selectionKey.channel();
        do {
            try {
                buffer.clear();
                clientAddr = channel.receive(buffer);
                if (clientAddr != null) {
                    rc.start();
                    buffer.flip();

                    Message queryMsg;
                    try {
                        queryMsg = new Message(buffer);
                    } catch (IOException ex) {
                        // Ignore invalid DNS messages
                        ex.printStackTrace();
                        continue;
                    }

                    if (log.isEnabled()) log.getLogger().info("query : " + queryMsg.getQuestion());

                    Record question = queryMsg.getQuestion();
                    if (question == null) continue;
                    SocketAddress refAddr = clientAddr;
                    if (executor != null)
                        // parallel processing
                        localExecutor.execute(() -> {
                            try {
                                processResponse(channel, refAddr, queryMsg, question);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        });
                    else
                        processResponse(channel, refAddr, queryMsg, question);
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


    private void processResponse(DatagramChannel channel, SocketAddress clientAddr, Message queryMsg, Record question)
            throws IOException {
        Message responseMsg = new Message(queryMsg.getHeader().getID());
        responseMsg.getHeader().setFlag(Flags.QR); // set as response
        responseMsg.addRecord(question, Section.QUESTION);

        String qName = question.getName().toString();


        if (log.isEnabled()) log.getLogger().info("qName: " + qName);

        InetAddress cachedHost = DNSRegistrar.SINGLETON.lookup(qName);
        if (question.getType() == Type.A && cachedHost != null) { // Handle locally if in customDomains and Type A query
            responseMsg.addRecord(new ARecord(question.getName(), DClass.IN, 60, cachedHost), Section.ANSWER);
        } else {

            // Forward to upstream resolver if no executor is present
            try {
                responseMsg = DNSRegistrar.SINGLETON.resolve(queryMsg);
                responseMsg.getHeader().setID(queryMsg.getHeader().getID());
            } catch (Exception ex) {
                // If upstream fails, just send empty response
                // Optionally set RCODE to SERVFAIL
                responseMsg.getHeader().setRcode(Rcode.SERVFAIL);
            }
        }

        try {
            localLock.lock();
            channel.send(ByteBuffer.wrap(responseMsg.toWire(DNS_BUFFER_SIZE)), clientAddr);
        } finally {
            localLock.unlock();
        }
    }


    /**
     * Returns the property description.
     *
     * @return description
     */
    @Override
    public String getDescription() {
        return "Java DNS cache";
    }

    /**
     * @return the name of the object
     */
    @Override
    public String getName() {
        return "DNSNIOProtocol";
    }

//    public ScheduledExecutorService getScheduler() {
//        return scheduler;
//    }
//
//    public void setScheduler(ScheduledExecutorService scheduler) {
//        this.scheduler = scheduler;
//    }
}
