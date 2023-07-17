package io.xlogistx.shiro.mgt;

import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.zoxweb.server.logging.LogWrapper;

public class ShiroSecurityManager extends DefaultSecurityManager {
    public static LogWrapper log = new LogWrapper(ShiroSecurityManager.class).setEnabled(true);

    public Subject createSubject(final SubjectContext subjectContext)
    {
        ShiroSecurityManager.log.getLogger().info("subjectContext:" + subjectContext);
        return super.createSubject(subjectContext);

    }
}
