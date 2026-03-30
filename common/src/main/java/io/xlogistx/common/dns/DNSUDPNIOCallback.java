package io.xlogistx.common.dns;

import org.xbill.DNS.*;
import org.xbill.DNS.Record;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.DataPacket;
import org.zoxweb.server.net.common.UDPSessionCallback;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;

public class DNSUDPNIOCallback
        extends UDPSessionCallback {
    public static final int DNS_BUFFER_SIZE = 4096;
    public static final LogWrapper log = new LogWrapper(DNSUDPNIOCallback.class).setEnabled(false);


    public DNSUDPNIOCallback(int port) {
        super(null, port, DNS_BUFFER_SIZE);
    }


    /**
     * Performs this operation on the given argument.
     *
     * @param dp the input argument
     */
    @Override
    public void accept(DataPacket dp) throws IOException {
        Message queryMsg;
        // the dp.getBuffer() is already flipped
        byte[] data = ByteBufferUtil.allocateByteArray(dp.getBuffer(), false);
        try {
            if (log.isEnabled()) log.getLogger().info(dp.getID() + " Data buffer size: " + data.length);

            queryMsg = new Message(data);


            if (log.isEnabled()) log.getLogger().info("query : " + queryMsg.getQuestion());

            Record question = queryMsg.getQuestion();
            if (question == null) {
                // the query should go nowhere
                return;
            }

            Message sinkResponse = DNSRegistrar.SINGLETON.sinkHoleResponse(queryMsg);
            if (sinkResponse != null) {
                // return 0.0.0.0 since the current domain is blacklisted
                send(ByteBuffer.wrap(sinkResponse.toWire(getBufferSize())), dp.getAddress(), false);
                return;
            }

            Message responseMsg = new Message(queryMsg.getHeader().getID());
            responseMsg.getHeader().setFlag(Flags.QR); // set as response
            responseMsg.addRecord(question, Section.QUESTION);


            String qName = question.getName().toString();


            if (log.isEnabled()) log.getLogger().info("qName: " + qName);

            InetAddress cachedHost = DNSRegistrar.SINGLETON.lookup(qName);
            if (question.getType() == Type.A && cachedHost != null) {
                // Handle locally if in customDomains and Type A query is cached
                responseMsg.addRecord(new ARecord(question.getName(), DClass.IN, 60, cachedHost), Section.ANSWER);
            } else {

                // Resolve the query with the remote resolver
                try {
                    responseMsg = DNSRegistrar.SINGLETON.resolveRemotely(queryMsg);
                    responseMsg.getHeader().setID(queryMsg.getHeader().getID());
                } catch (Exception ex) {
                    // If upstream fails, just send empty response
                    // Optionally set RCODE to SERVFAIL
                    responseMsg.getHeader().setRcode(Rcode.SERVFAIL);
                }
            }
            send(ByteBuffer.wrap(responseMsg.toWire(getBufferSize())), dp.getAddress(), false);
        } finally {
            ByteBufferUtil.cache(data);
        }
    }

    @Override
    public void exception(Throwable e) {

    }
}







