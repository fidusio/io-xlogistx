package io.xlogistx.common.smtp;


import jakarta.mail.*;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

import java.util.Properties;

public class SMTPMailTest {
    public static void main(String[] args) throws Exception {
        int index = 0;
        String smtpHost = args[index++];
        int smtpPort = Integer.parseInt(args[index++]);
        String from = args[index++]; // replace
        String password = args[index++];// replace
        String to = args[index++];
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
//        props.put("mail.smtp.starttls.enable", "true");
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
        message.setSubject("Test Jakarta Mail Email");
        message.setText("Hello, this is a test email from Jakarta Mail!");

        Transport.send(message);
        System.out.println("Email sent!");
    }
}