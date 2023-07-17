package io.xlogistx.shiro.mgt;

import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.DefaultSubjectDAO;
import org.apache.shiro.mgt.SessionStorageEvaluator;
import org.apache.shiro.mgt.SubjectDAO;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.SessionContext;
import org.apache.shiro.session.mgt.SessionKey;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.util.LifecycleUtils;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSessionStorageEvaluator;
import org.apache.shiro.web.mgt.DefaultWebSubjectFactory;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.apache.shiro.web.session.mgt.ServletContainerSessionManager;
import org.apache.shiro.web.session.mgt.WebSessionManager;
import org.apache.shiro.web.subject.WebSubject;
import org.apache.shiro.web.subject.WebSubjectContext;
import org.apache.shiro.web.subject.support.DefaultWebSubjectContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;

public class DefaultWebSecurityManager extends DefaultSecurityManager implements WebSecurityManager {
    private static final Logger log = LoggerFactory.getLogger(org.apache.shiro.web.mgt.DefaultWebSecurityManager.class);
    /** @deprecated */
    @Deprecated
    public static final String HTTP_SESSION_MODE = "http";
    /** @deprecated */
    @Deprecated
    public static final String NATIVE_SESSION_MODE = "native";
    /** @deprecated */
    @Deprecated
    private String sessionMode;

    public DefaultWebSecurityManager() {
        final DefaultWebSessionStorageEvaluator webEvalutator = new DefaultWebSessionStorageEvaluator();
        ((DefaultSubjectDAO) subjectDAO).setSessionStorageEvaluator(webEvalutator);
        sessionMode = "http";
        setSubjectFactory(new DefaultWebSubjectFactory());
        setRememberMeManager(new CookieRememberMeManager());
        setSessionManager(new ServletContainerSessionManager());
//        webEvalutator.setSessionManager(this.getSessionManager());
    }

    public DefaultWebSecurityManager(final Realm singleRealm) {
        this();
        setRealm(singleRealm);
    }

    public DefaultWebSecurityManager(final Collection<Realm> realms) {
        this();
        setRealms(realms);
    }

    protected SubjectContext createSubjectContext() {
        return new DefaultWebSubjectContext();
    }

    public void setSubjectDAO(final SubjectDAO subjectDAO) {
        super.setSubjectDAO(subjectDAO);
        applySessionManagerToSessionStorageEvaluatorIfPossible();
    }

    protected void afterSessionManagerSet() {
        super.afterSessionManagerSet();
        applySessionManagerToSessionStorageEvaluatorIfPossible();
    }

    private void applySessionManagerToSessionStorageEvaluatorIfPossible() {
        final SubjectDAO subjectDAO = getSubjectDAO();
        if (subjectDAO instanceof DefaultSubjectDAO) {
            final SessionStorageEvaluator evaluator = ((DefaultSubjectDAO)subjectDAO).getSessionStorageEvaluator();
            if (evaluator instanceof DefaultWebSessionStorageEvaluator) {
//                ((DefaultWebSessionStorageEvaluator)evaluator).setSessionManager(this.getSessionManager());
            }
        }

    }

    protected SubjectContext copy(final SubjectContext subjectContext) {
        return subjectContext instanceof WebSubjectContext ? new DefaultWebSubjectContext((WebSubjectContext)subjectContext) : super.copy(subjectContext);
    }

    /** @deprecated */
    @Deprecated
    public String getSessionMode() {
        return sessionMode;
    }

    /** @deprecated */
    @Deprecated
    public void setSessionMode(final String sessionMode) {
        DefaultWebSecurityManager.log.warn("The 'sessionMode' property has been deprecated.  Please configure an appropriate WebSessionManager instance instead of using this property.  This property/method will be removed in a later version.");
        if (null == sessionMode) {
            throw new IllegalArgumentException("sessionMode argument cannot be null.");
        } else {
            final String mode = sessionMode.toLowerCase();
            if (!"http".equals(mode) && !"native".equals(mode)) {
                final String msg = "Invalid sessionMode [" + sessionMode + "].  Allowed values are public static final String constants in the " + getClass().getName() + " class: '" + "http" + "' or '" + "native" + "', with '" + "http" + "' being the default.";
                throw new IllegalArgumentException(msg);
            } else {
                final boolean recreate = !mode.equals(this.sessionMode);
                this.sessionMode = mode;
                if (recreate) {
                    LifecycleUtils.destroy(getSessionManager());
                    final SessionManager sessionManager = createSessionManager(mode);
                    setInternalSessionManager(sessionManager);
                }

            }
        }
    }

    public void setSessionManager(final SessionManager sessionManager) {
        sessionMode = null;
        if (null != sessionManager && !(sessionManager instanceof WebSessionManager) && DefaultWebSecurityManager.log.isWarnEnabled()) {
            final String msg = "The " + getClass().getName() + " implementation expects SessionManager instances that implement the " + WebSessionManager.class.getName() + " interface.  The configured instance is of type [" + sessionManager.getClass().getName() + "] which does not implement this interface..  This may cause unexpected behavior.";
            DefaultWebSecurityManager.log.warn(msg);
        }

        setInternalSessionManager(sessionManager);
    }

    private void setInternalSessionManager(final SessionManager sessionManager) {
        super.setSessionManager(sessionManager);
    }

    public boolean isHttpSessionMode() {
        final SessionManager sessionManager = getSessionManager();
        return sessionManager instanceof WebSessionManager && ((WebSessionManager)sessionManager).isServletContainerSessions();
    }

    protected SessionManager createSessionManager(final String sessionMode) {
        if (sessionMode.equalsIgnoreCase("native")) {
            DefaultWebSecurityManager.log.info("{} mode - enabling DefaultWebSessionManager (non-HTTP and HTTP Sessions)", "native");
            return new DefaultWebSessionManager();
        } else {
            DefaultWebSecurityManager.log.info("{} mode - enabling ServletContainerSessionManager (HTTP-only Sessions)", "http");
            return new ServletContainerSessionManager();
        }
    }

    protected SessionContext createSessionContext(final SubjectContext subjectContext) {
        final SessionContext sessionContext = super.createSessionContext(subjectContext);
//        if (subjectContext instanceof WebSubjectContext) {
//            WebSubjectContext wsc = (WebSubjectContext)subjectContext;
//            ServletRequest request = wsc.resolveServletRequest();
//            ServletResponse response = wsc.resolveServletResponse();
//            DefaultWebSessionContext webSessionContext = new DefaultWebSessionContext((Map)sessionContext);
//            if (request != null) {
//                webSessionContext.setServletRequest(request);
//            }
//
//            if (response != null) {
//                webSessionContext.setServletResponse(response);
//            }
//
//            sessionContext = webSessionContext;
//        }

        return sessionContext;
    }

    protected SessionKey getSessionKey(final SubjectContext context) {
//        if (WebUtils.isWeb(context)) {
//            Serializable sessionId = context.getSessionId();
//            ServletRequest request = WebUtils.getRequest(context);
//            ServletResponse response = WebUtils.getResponse(context);
//            return new WebSessionKey(sessionId, request, response);
//        } else {
            return super.getSessionKey(context);
//        }
    }

    protected void beforeLogout(final Subject subject) {
        super.beforeLogout(subject);
        removeRequestIdentity(subject);
    }

    protected void removeRequestIdentity(final Subject subject) {
        if (subject instanceof WebSubject) {
            final WebSubject webSubject = (WebSubject)subject;
//            ServletRequest request = webSubject.getServletRequest();
//            if (request != null) {
//                request.setAttribute(ShiroHttpServletRequest.IDENTITY_REMOVED_KEY, Boolean.TRUE);
//            }
        }

    }
}
