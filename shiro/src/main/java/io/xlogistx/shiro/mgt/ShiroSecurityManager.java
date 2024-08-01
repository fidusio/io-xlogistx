package io.xlogistx.shiro.mgt;

import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.security.AccessException;

public class ShiroSecurityManager extends DefaultSecurityManager {
    public static LogWrapper log = new LogWrapper(ShiroSecurityManager.class).setEnabled(true);
    private boolean blockMainThread = true;
//    public Subject createSubject(SubjectContext subjectContext)
//    {
//        log.getLogger().info("subjectContext:" + subjectContext);
//        return super.createSubject(subjectContext);
//    }




    public Subject createSubject(SubjectContext subjectContext) {

        if (isMainThreadBlocked() && TaskUtil.isMainThread())
            throw new AccessException("Can not login via the main app thread");
        return super.createSubject(subjectContext);
    }

    public boolean isMainThreadBlocked()
    {
        return blockMainThread;
    }

    public void setMainThreadBlocked(boolean stat)
    {
        this.blockMainThread = stat;
    }
}
