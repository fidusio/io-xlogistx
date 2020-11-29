package io.xlogistx.common.test;




import io.xlogistx.common.smtp.Recipient;
import io.xlogistx.common.smtp.SMTPMessage;
import io.xlogistx.common.smtp.SMTPSender;
import io.xlogistx.shared.data.SMTPConfig;

import java.util.Arrays;

import java.util.Date;
import java.util.logging.Logger;

public class SMTPAPITester {

    private static final Logger log = Logger.getLogger(SMTPAPITester.class.getName());


    public static void main(String ...args)
    {
      try
      {
          int index = 0;
          String from = args[index++];
          String user = args[index++];
          String password = args[index++];
          String host = args[index++];
          int port = Integer.parseInt(args[index++]);
          String subject = args[index++];
          String message = new Date() + " " + args[index++];
          String [] to = Arrays.copyOfRange(args, index, args.length);


          String emails = "To:xlogistx@xlogistx.io, bcc:batata@batata.com, CC: ccd@email.com, tO: xlogistx@xlogistx.io";

          System.out.println(Arrays.toString(Recipient.toRecipients(emails)));

          //sendSMTPS(from, new SMTPMessage(subject, message), new SMTPConfig(host, port, user, password), to);
          SMTPSender.sendEmails(new SMTPConfig(host, port, user, password), from, new SMTPMessage(subject, message), Recipient.toRecipients(Recipient.Type.TO, to));
          log.info("Message Sent Successfully from:" +  from + "\nto:" + Arrays.toString(to));
      }
      catch(Exception e)
      {
          e.printStackTrace();
      }
    }
}
