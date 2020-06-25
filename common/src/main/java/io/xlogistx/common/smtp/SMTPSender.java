package io.xlogistx.common.smtp;

import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.logging.Logger;

public class SMTPSender {

    private static final Logger log = Logger.getLogger(SMTPSender.class.getName());
    private SMTPSender() {}


    /**
     * This method will send secure smtp message
     * @param cfg smtp server configuration
     * @param from sender email
     * @param msg message content
     * @param recipients list of recipients
     * @throws MessagingException
     */
    public static void sendSMTPS(SMTPConfig cfg,
                                 String from,
                                 SMTPMessage msg,
                                 Recipient ...recipients) throws MessagingException {
        //Get properties object
        Properties props = new Properties();
        props.put("mail.smtp.host", cfg.host);
        props.put("mail.smtp.port", ""+cfg.port);
        props.put("mail.smtp.socketFactory.port", ""+cfg.port);
        props.put("mail.smtp.starttls.enable","true");
        props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
        props.put("mail.smtp.socketFactory.fallback", "false");
        props.put("mail.smtp.auth", "true");
        //props.put("mail.debug", "true");

        //get Session
        Session session = Session.getInstance(props,
                new javax.mail.Authenticator() {
                    protected PasswordAuthentication getPasswordAuthentication() {
                        //log.info(user + ":" + password + " " + Thread.currentThread());
                        return new PasswordAuthentication(cfg.user, cfg.password);
                    }
                });
        //compose message

        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress(from));
        for (Recipient recipient : recipients)
        {
            switch (recipient.type)
            {
                case TO:
                    message.addRecipient(Message.RecipientType.TO, new InternetAddress(recipient.email));
                    break;
                case CC:
                    message.addRecipient(Message.RecipientType.CC, new InternetAddress(recipient.email));
                    break;
                case BCC:
                    message.addRecipient(Message.RecipientType.BCC, new InternetAddress(recipient.email));
                    break;
            }


        }

        message.setSubject(msg.subject);
        message.setText(msg.message);
        //send message
        Transport transport = session.getTransport("smtps");
        transport.connect(cfg.host, cfg.port, cfg.user, cfg.password);
        Transport.send(message);
    }
}
