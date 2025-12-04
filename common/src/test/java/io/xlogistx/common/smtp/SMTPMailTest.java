package io.xlogistx.common.smtp;


import io.xlogistx.shared.data.SMTPConfig;
import jakarta.mail.*;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

import java.util.Properties;

public class SMTPMailTest {
    public static void main(String[] args) throws Exception {
        try {
            int index = 0;
            String smtpHost = args[index++];
            int smtpPort = Integer.parseInt(args[index++]);
            String from = args[index++]; // replace
            String password = args[index++];// replace
            String to = args[index++];

            Properties props = new Properties();
            props.put("mail.smtp.auth", "true");
            //props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.host", smtpHost);
            props.put("mail.smtp.ssl.enable", "true");
            props.put("mail.smtp.port", String.valueOf(smtpPort));
            props.put("mail.smtp.ssl.trust", smtpHost);
            // props.put("mail.debug", "true"); // Uncomment to debug

            Session session = Session.getInstance(props, new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(from, password);
                }
            });

            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(from));
            message.setRecipients(Message.RecipientType.TO,
                    InternetAddress.parse(to));
            int counter = 0;
            message.setSubject("Test Jakarta Mail Email " + ++counter);
            message.setText("Hello, this is a test email from Jakarta Mail!");

            Transport.send(message);

            SMTPConfig smtpConfig = new SMTPConfig();
            smtpConfig.setHost(smtpHost);
            smtpConfig.setPort(smtpPort);
            smtpConfig.setUser(from);
            smtpConfig.setPassword(password);
            smtpConfig.setTrusted(true);

            SMTPMessage smtpMessage = new SMTPMessage();
            smtpMessage.setSubject("Testing email " + ++counter);
            smtpMessage.addRecipient(EmailRecipient.Type.TO, to);
            smtpMessage.setContent("Simple Test content.");
            System.out.println(SMTPSender.sendEmail(smtpConfig, smtpMessage));

            System.out.println("Email sent!");
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("usage: smtphost port senderEmail senderMailPassword recipientEmail");
        }
    }
}