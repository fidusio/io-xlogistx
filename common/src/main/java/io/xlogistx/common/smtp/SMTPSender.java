package io.xlogistx.common.smtp;


import io.xlogistx.shared.data.SMTPConfig;

import javax.mail.*;

import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import java.util.LinkedHashSet;
import java.util.Properties;
import java.util.Set;


public class SMTPSender
{

    private SMTPSender() {}

    /**
     * Send an email message
     * @param cfg the smtp server config user must use secure server config
     * @param smtpMessage to be send
     * @return STMPMessage with canonical ID set.
     * @throws MessagingException in case of failure
     */
    public static SMTPMessage sendEmail(SMTPConfig cfg,
                                        SMTPMessage smtpMessage)
            throws MessagingException
    {
        //Get properties object
        Properties props = new Properties();
        props.put("mail.smtp.host", cfg.getHost());
        props.put("mail.smtp.port", ""+cfg.getPort());
        props.put("mail.smtp.socketFactory.port", ""+cfg.getPort());
        props.put("mail.smtp.starttls.enable","true");
        props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
        props.put("mail.smtp.socketFactory.fallback", "false");
        props.put("mail.smtp.auth", "true");
        //props.put("mail.debug", "true");

        //get Session
        Session session = Session.getInstance(props,
                new javax.mail.Authenticator() {
                    protected PasswordAuthentication getPasswordAuthentication() {
                        //log.info(cfg.user + ":" + cfg.password + " " + Thread.currentThread());
                        return new PasswordAuthentication(cfg.getUser(), cfg.getPassword());
                    }
                });
        //compose message

        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress(smtpMessage.getFrom()));


        setRecipients(EmailRecipient.Type.TO, message, smtpMessage.getTo());
        setRecipients(EmailRecipient.Type.CC, message, smtpMessage.getCC());
        setRecipients(EmailRecipient.Type.BCC, message, smtpMessage.getBCC());
        setRecipients(EmailRecipient.Type.REPLY_TO, message, smtpMessage.getReplyTo());



        message.setSubject(smtpMessage.getSubject());
        message.setText(smtpMessage.getContent());
        //send message
        Transport transport = session.getTransport("smtps");
        transport.connect(cfg.getHost(), cfg.getPort(), cfg.getUser(), cfg.getPassword());
        Transport.send(message);
        smtpMessage.setCanonicalID(message.getMessageID());

        return smtpMessage;
    }

    private static void setRecipients(EmailRecipient.Type type, Message message, String ...recipients) throws MessagingException {
        Set<Address> replyTo = new LinkedHashSet<Address>();


        for(String recipient : recipients ) {
            switch (type) {
                case TO:
                    message.addRecipient(Message.RecipientType.TO, new InternetAddress(recipient));
                    break;
                case CC:
                    message.addRecipient(Message.RecipientType.CC, new InternetAddress(recipient));
                    break;
                case BCC:
                    message.addRecipient(Message.RecipientType.BCC, new InternetAddress(recipient));
                    break;
                case REPLY_TO:
                    replyTo.add(new InternetAddress(recipient));
                    break;
            }
        }
        if(replyTo.size() > 0)
            message.setReplyTo(replyTo.toArray(new InternetAddress[replyTo.size()]));
    }
}
