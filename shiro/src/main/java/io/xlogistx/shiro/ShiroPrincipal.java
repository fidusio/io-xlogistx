package io.xlogistx.shiro;

import org.apache.shiro.subject.Subject;

import java.security.Principal;

// Simple Principal implementation wrapping Shiro Subject
public class ShiroPrincipal implements Principal {

    private final Subject subject;

    public ShiroPrincipal(Subject subject) {
        this.subject = subject;
    }

    @Override
    public String getName() {
        return primaryPrincipalToString(subject);
    }

    public int hashCode()
    {
        return subject.hashCode();
    }
    public boolean equals(Object another)
    {
        if(another instanceof ShiroPrincipal)
        {
            another = ((ShiroPrincipal) another).subject;
        }
        if(another instanceof Subject)
        {
            return subject.equals(another);
        }

        return false;
    }


    public Subject getSubject()
    {
        return subject;
    }

    @Override
    public String toString() {
        return getName();
    }


    public static String primaryPrincipalToString(Subject subject) {
        return subject != null ? subject.getPrincipal().toString() : "anonymous";
    }


}
