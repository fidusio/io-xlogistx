package io.xlogistx.common.smtp;

import org.zoxweb.shared.data.CanonicalIDDAO;

import org.zoxweb.shared.filters.FilterType;
import org.zoxweb.shared.util.*;


public class SMTPMessage
    extends CanonicalIDDAO
{

    public enum Param
            implements GetNVConfig
    {

        FROM(NVConfigManager.createNVConfig("from", "From", "From", true, true, false, false, String.class, FilterType.EMAIL)),
        TO(NVConfigManager.createNVConfig("to", "To destination", "To", true, true, NVStringList.class)),
        CC(NVConfigManager.createNVConfig("cc", "Carbon Copy", "Cc", true, true, NVStringList.class)),
        BCC(NVConfigManager.createNVConfig("bcc", "Blind Carbon Copy", "Bcc", true, true, NVStringList.class)),
        REPLY_TO(NVConfigManager.createNVConfig("reply_to", "Reply To", "Reply-To", true, true, NVStringList.class)),
        SUBJECT(NVConfigManager.createNVConfig("subject", "Subject", "Subject", true, true, String.class)),
        CONTENT(NVConfigManager.createNVConfig("content", "Message content", "Content", true, true, String.class)),
        ;
        private final NVConfig nvc;

        Param(NVConfig nvc)
        {
            this.nvc = nvc;
        }

        public NVConfig getNVConfig()
        {
            return nvc;
        }
    }



    public static final NVConfigEntity NVC_SMTP_MESSAGE = new NVConfigEntityLocal
            (
                    "smtp_message",
                    null,
                    "SMTPMessage",
                    true,
                    false,
                    false,
                    false,
                    SMTPMessage.class,
                    SharedUtil.extractNVConfigs(Param.values()),
                    null,
                    false,
                    CanonicalIDDAO.NVC_CANONICAL_ID_DAO
            );



    public SMTPMessage()
    {
        super(NVC_SMTP_MESSAGE);
    }
    public SMTPMessage(String subject, String message)
    {
        this();
        setSubject(subject);
        setContent(message);
    }


    public void setFrom(String from)
    {
        setValue(Param.FROM, from);
    }

    public String getFrom()
    {
        return lookupValue(Param.FROM);
    }

    public void setSubject(String subject)
    {
        setValue(Param.SUBJECT, subject);
    }

    public String getSubject()
    {
        return lookupValue(Param.SUBJECT);
    }


    public void setContent(String content)
    {
        setValue(Param.CONTENT, content);
    }

    public String getContent()
    {
        return lookupValue(Param.CONTENT);
    }


    public String[] getTo()
    {
        return ((NVStringList) lookup(Param.TO)).getValues();
    }

    public String[] getBCC()
    {
        return ((NVStringList) lookup(Param.BCC)).getValues();
    }

    public String[] getCC()
    {
        return ((NVStringList) lookup(Param.CC)).getValues();
    }


    public String[] getReplyTo()
    {
        return ((NVStringList) lookup(Param.REPLY_TO)).getValues();
    }


    public void addRecipients(EmailRecipient ... recipients)
    {
        for(EmailRecipient recipient : recipients)
        {
            addRecipient(recipient.getRecipientType(), recipient.getEmail());
        }
    }

    public void addRecipient(EmailRecipient.Type type, String email)
    {
        if(type == null)
            type = EmailRecipient.Type.TO;
        email = FilterType.EMAIL.validate(email);
        NVStringList toAdd = null;
        switch (type)
        {

            case TO:
                toAdd = (NVStringList) lookup(Param.TO);
                break;
            case CC:
                toAdd = (NVStringList) lookup(Param.CC);
                break;
            case BCC:
                toAdd = (NVStringList) lookup(Param.BCC);
                break;
            case REPLY_TO:
                toAdd = (NVStringList) lookup(Param.REPLY_TO);
                break;
        }
        toAdd.getValue().add(email);
    }



}