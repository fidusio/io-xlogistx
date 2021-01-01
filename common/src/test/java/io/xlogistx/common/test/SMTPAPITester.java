package io.xlogistx.common.test;




import io.xlogistx.common.smtp.EmailRecipient;
import io.xlogistx.common.smtp.SMTPMessage;
import io.xlogistx.common.smtp.SMTPSender;
import io.xlogistx.shared.data.SMTPConfig;
import org.zoxweb.server.util.GSONUtil;

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


          String emails = "To:xlogistx@xlogistx.io, bcc:batata@batata.com, CC: ccd@email.com, tO: xlogistx@xlogistx.io, reply-to:authority@batata.io";

          System.out.println(Arrays.toString(EmailRecipient.toRecipients(emails)));


          String[] emailsToTest ={"batata.com", "batata@batata.com"};
          for (String email : emailsToTest)
          {
              try
              {
                  EmailRecipient.toRecipients(email);
              }
              catch(Exception e)
              {
                  e.printStackTrace();
              }
          }

          //sendSMTPS(from, new SMTPMessage(subject, message), new SMTPConfig(host, port, user, password), to);
          SMTPMessage smtpMessage = new SMTPMessage(subject, message);
          smtpMessage.setFrom(from);

          smtpMessage.addRecipients(EmailRecipient.toRecipients(EmailRecipient.Type.TO, to));
          smtpMessage.addRecipients(EmailRecipient.toRecipients(emails));
          log.info(GSONUtil.toJSON(smtpMessage, true, false, false));
          SMTPSender.sendEmail(new SMTPConfig(host, port, user, password), smtpMessage);
          log.info("Message Sent Successfully from:" +  from + "\nto:" + Arrays.toString(to) +" message id:" + smtpMessage.getCanonicalID());
      }
      catch(Exception e)
      {
          e.printStackTrace();
      }
    }
}
