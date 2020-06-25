package io.xlogistx.common.test;




import io.xlogistx.common.smtp.Recipient;
import io.xlogistx.common.smtp.SMTPConfig;
import io.xlogistx.common.smtp.SMTPMessage;
import io.xlogistx.common.smtp.SMTPSender;

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

          //sendSMTPS(from, new SMTPMessage(subject, message), new SMTPConfig(host, port, user, password), to);
          SMTPSender.sendSMTPS(new SMTPConfig(host, port, user, password), from, new SMTPMessage(subject, message), Recipient.multiCreate(Recipient.Type.CC, to));
          log.info("Message Sent Successfully from:" +  from + "\nto:" + Arrays.toString(to));
      }
      catch(Exception e)
      {
          e.printStackTrace();
      }
    }
}
