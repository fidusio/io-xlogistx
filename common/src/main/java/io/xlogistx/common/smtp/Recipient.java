package io.xlogistx.common.smtp;

import java.util.ArrayList;
import java.util.List;

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
        this.type = type;
        this.email = email;
    }

    public static Recipient create(Type type, String email)
    {
        return new Recipient(type,email);
    }

    public static Recipient[] multiCreate(Type type, String ...emails)
    {
        List<Recipient> recipients = new ArrayList<Recipient>();
        for(String email : emails)
            recipients.add(create(type, email));

        return recipients.toArray(new Recipient[0]);
    }

}