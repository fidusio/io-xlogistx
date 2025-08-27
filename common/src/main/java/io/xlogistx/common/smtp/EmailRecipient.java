package io.xlogistx.common.smtp;

import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.filters.FilterType;
import org.zoxweb.shared.util.*;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class EmailRecipient
        extends SetNameDescriptionDAO {
    public enum Type
            implements GetName {
        // Destination recipient
        TO("to"),
        // Carbon Copy
        CC("cc"),
        // Blind Carbon Copy
        BCC("bcc"),
        // Reply To email, non standard type
        REPLY_TO("reply-to"),
        ;

        private final String name;

        Type(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }
    }


    public enum Param
            implements GetNVConfig {

        EMAIL(NVConfigManager.createNVConfig("email", "Email", "Email", true, true, false, false, String.class, FilterType.EMAIL)),
        TYPE(NVConfigManager.createNVConfig("type", "Recipient type", "Type", true, true, Type.class)),
        ;
        private final NVConfig nvc;

        Param(NVConfig nvc) {
            this.nvc = nvc;
        }

        public NVConfig getNVConfig() {
            return nvc;
        }
    }

    public static final NVConfigEntity NVC_EMAIL_RECIPIENT = new NVConfigEntityPortable(
            "email_recipient",
            null,
            "EmailRecipient",
            true,
            false,
            false,
            false,
            EmailRecipient.class,
            SharedUtil.extractNVConfigs(Param.values()),
            null,
            false,
            SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO
    );


    public EmailRecipient() {
        super(NVC_EMAIL_RECIPIENT);
    }

    private EmailRecipient(Type type, String email) {
        this();
        setEmail(email);
        setRecipientType(type != null ? type : Type.TO);
    }

    public String getEmail() {
        return lookupValue(Param.EMAIL);
    }

    public void setEmail(String email) {
        setValue(Param.EMAIL, email);
    }


    public Type getRecipientType() {
        return lookupValue(Param.TYPE);
    }

    public void setRecipientType(Type type) {
        setValue(Param.TYPE, type);
    }

    public static EmailRecipient toRecipient(Type type, String email) {
        return new EmailRecipient(type, email);
    }

    public String toString() {
        return getRecipientType().name().toLowerCase() + ":" + getEmail();
    }


    public boolean equals(Object obj) {
        if (obj != null)
            return toString().equalsIgnoreCase(obj.toString());
        return false;
    }

    public int hashCode() {
        return toString().hashCode();
    }

    public static EmailRecipient[] toRecipients(Type type, String... emails) {
        List<EmailRecipient> recipients = new ArrayList<EmailRecipient>();
        for (String email : emails)
            recipients.add(toRecipient(type, email));

        return recipients.toArray(new EmailRecipient[0]);
    }


    private static EmailRecipient toRecipient(String email) {
        String[] parsed = email.split(":");

        for (int i = 0; i < parsed.length; i++) {
            parsed[i] = SharedStringUtil.trimOrNull(parsed[i]);
        }

        if (parsed.length == 1)
            return toRecipient(Type.TO, parsed[0]);
        else if (parsed.length == 2)
            return toRecipient(SharedUtil.enumValue(Type.class, parsed[0]), parsed[1]);

        throw new IllegalArgumentException("Invalid Email format " + email);
    }


    /**
     * Parse comma separated email string ie: "to:user@email.com, cc:another@email.com, reply-to:sender@email.com"
     * @param emails as comma separated string
     * @return array of EmailRecipient objects
     */
    public static EmailRecipient[] toRecipients(String emails) {
        String[] parsed = emails.split(",");

        Set<EmailRecipient> recipients = new LinkedHashSet<EmailRecipient>();
        for (String email : parsed)
            recipients.add(toRecipient(email));
        return recipients.toArray(new EmailRecipient[0]);
    }


}