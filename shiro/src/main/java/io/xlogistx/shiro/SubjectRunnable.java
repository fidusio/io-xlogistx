package io.xlogistx.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;



public abstract class SubjectRunnable
        implements Runnable
{
    protected final Subject subject;

    protected SubjectRunnable()
    {
        this(SecurityUtils.getSubject());
    }

    protected SubjectRunnable(Subject subject)
    {
        this.subject = subject;
    }



}
