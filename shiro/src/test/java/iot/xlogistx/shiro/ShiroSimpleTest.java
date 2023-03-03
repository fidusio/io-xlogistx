package iot.xlogistx.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.env.BasicIniEnvironment;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.zoxweb.server.logging.LogWrapper;


public class ShiroSimpleTest
{

    public static final LogWrapper log = new LogWrapper(ShiroSimpleTest.class);
    public static void main(String ...args)
    {
        try
        {

            int index = 0 ;
            String user = args[index++];
            String password = args[index++];

            BasicIniEnvironment env = new BasicIniEnvironment("classpath:shiro-simple.ini");

            SecurityManager securityManager  = env.getSecurityManager();
            SecurityUtils.setSecurityManager(securityManager);

            if (securityManager == SecurityUtils.getSecurityManager())
            {
                log.getLogger().info("" +securityManager);
            }
            Subject subject = SecurityUtils.getSubject();
            UsernamePasswordToken authcToken  = new UsernamePasswordToken(user, password);
            subject.login(authcToken);
            log.getLogger().info("is authenticated " + subject.isAuthenticated() + " " + subject.getPrincipals().getPrimaryPrincipal());
            subject.logout();

            log.getLogger().info("is authenticated " + subject.isAuthenticated() + " " + subject.getPrincipals());

        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }

}
