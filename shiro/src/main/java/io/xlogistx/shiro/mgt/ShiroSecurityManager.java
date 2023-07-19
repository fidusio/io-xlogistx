package io.xlogistx.shiro.mgt;

import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.zoxweb.server.logging.LogWrapper;

public class ShiroSecurityManager extends DefaultSecurityManager {
    public static LogWrapper log = new LogWrapper(ShiroSecurityManager.class).setEnabled(true);

//    public Subject createSubject(SubjectContext subjectContext)
//    {
//        log.getLogger().info("subjectContext:" + subjectContext);
//        return super.createSubject(subjectContext);
//    }

    public Subject createSubject(SubjectContext subjectContext) {

        //log.getLogger().info("subjectContext:" + subjectContext);
        //create a copy so we don't modify the argument's backing map:
        SubjectContext context = copy(subjectContext);

        //ensure that the context has a SecurityManager instance, and if not, add one:
        context = ensureSecurityManager(context);

        //Resolve an associated Session (usually based on a referenced session ID), and place it in the context before
        //sending to the SubjectFactory.  The SubjectFactory should not need to know how to acquire sessions as the
        //process is often environment specific - better to shield the SF from these details:
        context = resolveSession(context);

        //Similarly, the SubjectFactory should not require any concept of RememberMe - translate that here first
        //if possible before handing off to the SubjectFactory:
        context = resolvePrincipals(context);



        Subject subject = doCreateSubject(context);
        //log.getLogger().info("After doCreateSubject: " + subject);

        //save this subject for future reference if necessary:
        //(this is needed here in case rememberMe principals were resolved and they need to be stored in the
        //session, so we don't constantly rehydrate the rememberMe PrincipalCollection on every operation).
        //Added in 1.2:
        save(subject);

        return subject;
    }
}
