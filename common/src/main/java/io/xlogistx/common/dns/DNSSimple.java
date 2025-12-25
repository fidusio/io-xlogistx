package io.xlogistx.common.dns;


import org.xbill.DNS.*;
import org.xbill.DNS.Record;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.util.GetNameValue;
import org.zoxweb.shared.util.ParamUtil;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class DNSSimple {

    public static final LogWrapper log = new LogWrapper(DNSSimple.class).setEnabled(true);
    // Map for custom overrides
    static Map<String, String> customMap = new LinkedHashMap<>();

    static void syncProcessing() throws IOException {
        customMap.put("dbs.xlogistx.io.", "10.0.0.6");

        DatagramSocket socket = new DatagramSocket(53);
        byte[] buf = new byte[512];

        Resolver upstream = new SimpleResolver("10.0.0.1");

        while (true) {
            DatagramPacket packet = new DatagramPacket(buf, buf.length);
            socket.receive(packet);

            Message query = new Message(packet.getData());

            if (log.isEnabled()) log.getLogger().info("query : " + query);

            Record question = query.getQuestion();
            String qname = question.getName().toString().toLowerCase();

            Message response = new Message(query.getHeader().getID());
            response.getHeader().setFlag(Flags.QR);
            response.addRecord(question, Section.QUESTION);

            try {
                // Custom resolution
                if (question.getType() == Type.A && customMap.containsKey(qname)) {
                    String ip = customMap.get(qname);
                    Record answer = new ARecord(
                            question.getName(), DClass.IN, 60,
                            InetAddress.getByName(ip)
                    );
                    response.addRecord(answer, Section.ANSWER);
                } else {
                    // Forward to upstream (e.g. 8.8.8.8)
//                byte[] out = query.toWire();
//                Message upstreamResponse = upstream.send(query);
                    response = upstream.send(query); // Just use the upstream response
                    response.getHeader().setID(query.getHeader().getID()); // preserve transaction ID
                }

                byte[] respData = response.toWire(512);
                DatagramPacket respPacket = new DatagramPacket(
                        respData, respData.length, packet.getAddress(), packet.getPort()
                );
                socket.send(respPacket);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {

        try {

            ParamUtil.ParamMap params = ParamUtil.parse("=", args);
            String resolver = params.stringValue("resolver", false);

            DNSRegistrar.SINGLETON.setResolver(resolver);
            int port = params.intValue("port", 53);
            List<GetNameValue<String>> hosts = ParamUtil.parseGroupedValues(params.stringValue("dns", true));
            System.out.println("To cache " + hosts);
            for (GetNameValue<String> gnvs : hosts)
                DNSRegistrar.SINGLETON.register(gnvs);

            DNSUDPNIOProtocol.log.setEnabled(true);
            //syncProcessing()
            NIOSocket nioSocket = new NIOSocket(TaskUtil.defaultTaskProcessor(), TaskUtil.defaultTaskScheduler());
            nioSocket.addDatagramSocket(new InetSocketAddress(port), DNSUDPNIOFactory.SINGLETON);


        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("uasage resolver=8.8.8.8 [port=53] [dns=(localdb,192.168.1.52),(localbroker,10.0.1.78)]");
            System.exit(-1);
        }
    }
}


