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
            if (question == null)
                return;


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
            send(ByteBuffer.wrap(responseMsg.toWire(getBufferSize())), dp.getAddress());
        }
        finally {
            ByteBufferUtil.cache(data);
        }
    }
}







