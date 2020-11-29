package io.xlogistx.common.smtp;

import org.zoxweb.shared.filters.FilterType;
import org.zoxweb.shared.util.SharedStringUtil;
import org.zoxweb.shared.util.SharedUtil;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class Recipient
{
    public enum Type
    {
        TO,
        CC,
        BCC
    }

    public final String email;
    public final Type type;

    private Recipient(Type type, String email)
    {
        email = FilterType.EMAIL.validate(email);
        this.type = type != null ? type : Type.TO;
        this.email = email;
    }

    public static Recipient toRecipient(Type type, String email)
    {
        return new Recipient(type,email);
    }

    public String toString()
    {
        return type.name().toLowerCase() + ":" + email;
    }


    public boolean equals(Object obj)
    {
        if(obj != null)
            return toString().equalsIgnoreCase(obj.toString());
        return false;
    }

    public int hashCode()
    {
        return toString().hashCode();
    }

    public static Recipient[] toRecipients(Type type, String ...emails)
    {
        List<Recipient> recipients = new ArrayList<Recipient>();
        for(String email : emails)
            recipients.add(toRecipient(type, email));

        return recipients.toArray(new Recipient[0]);
    }


    private static Recipient toRecipient(String email)
    {
        String[] parsed = email.split(":");

        for (int i=0; i < parsed.length; i++)
            parsed[i] = SharedStringUtil.trimOrNull(parsed[i]);

        if(parsed.length == 1)
            return toRecipient(Type.TO, parsed[0]);
        else if(parsed.length == 2)
            return toRecipient(SharedUtil.enumValue(Type.class, parsed[0]), parsed[1]);

        throw new IllegalArgumentException("Invalid Email format " + email);
    }

    public static Recipient[] toRecipients(String emails)
    {
        String[] parsed = emails.split(",");

        Set<Recipient> recipients = new LinkedHashSet<Recipient>();
        for (String email : parsed)
            recipients.add(toRecipient(email));
        return recipients.toArray(new Recipient[0]);
    }



}