package io.xlogistx.shiro.mgt;

import io.xlogistx.shiro.ShiroSession;
import io.xlogistx.shiro.ShiroUtil;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionListener;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;

public class ShiroSessionListener implements SessionListener {


    public static final LogWrapper log = new LogWrapper(ShiroSessionListener.class).setEnabled(false);

    @Override
    public void onStart(Session session) {
        if (log.isEnabled())
            log.getLogger().info("started: " + ShiroUtil.toString(session));
    }

    @Override
    public void onStop(Session session) {
        if (log.isEnabled()) log.getLogger().info("stopped: " + ShiroUtil.toString(session));
        ShiroSession<?> shiroSession = (ShiroSession<?>) session.getAttribute(ShiroSession.SHIRO_SESSION);
        if (log.isEnabled()) log.getLogger().info("ShiroSession: " + shiroSession);
        if (shiroSession != null) {
            IOUtil.close(shiroSession);
        }

    }

    @Override
    public void onExpiration(Session session) {
        if (log.isEnabled()) log.getLogger().info("expired: " + ShiroUtil.toString(session));
    }


}
