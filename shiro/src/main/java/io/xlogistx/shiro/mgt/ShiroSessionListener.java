package io.xlogistx.shiro.mgt;

import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionListener;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.zoxweb.server.logging.LogWrapper;

public class ShiroSessionListener implements SessionListener {


    DefaultSessionManager dsm;
    public static final LogWrapper log = new LogWrapper(ShiroSessionListener.class).setEnabled(true);

    @Override
    public void onStart(Session session) {
        log.getLogger().info("started: " + session );
        session.setAttribute("toto", "toto");
    }

    @Override
    public void onStop(Session session) {
        log.getLogger().info("stopped: " + session) ;
    }

    @Override
    public void onExpiration(Session session) {
        log.getLogger().info("expired: " + session);
    }
}
