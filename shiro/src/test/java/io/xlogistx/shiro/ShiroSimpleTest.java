package io.xlogistx.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.env.BasicIniEnvironment;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.logging.LoggerUtil;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.util.RateCounter;


public class ShiroSimpleTest
{

    public static final LogWrapper log = new LogWrapper(ShiroSimpleTest.class).setEnabled(true);
    public static void main(String ...args)
    {
        LoggerUtil.enableDefaultLogger("io.xlogistx");
        try
        {

            RateCounter rateCounter = new RateCounter("shiro-tester");
            int index = 0 ;
            String user = args[index++];
            String password = args[index++];
            int repeat = args.length > index ? Integer.parseInt(args[index++]) : 1;

            BasicIniEnvironment env = new BasicIniEnvironment("classpath:shiro-simple.ini");

            SecurityManager securityManager  = env.getSecurityManager();
            SecurityUtils.setSecurityManager(securityManager);

            if (securityManager == SecurityUtils.getSecurityManager())
            {
                log.getLogger().info("" +securityManager);
            }
            Subject subject = SecurityUtils.getSubject();
            UsernamePasswordToken authcToken  = new UsernamePasswordToken(user, password);
            long timestamp = System.currentTimeMillis();
            for(int i=0; i < repeat; i++) {
                subject.login(authcToken);
                //log.getLogger().info("is authenticated " + subject.isAuthenticated() + " " + subject.getPrincipals().getPrimaryPrincipal());
                subject.logout();
                timestamp = rateCounter.registerTimeStamp(timestamp);
            }
            //subject.login(authcToken);

            log.getLogger().info("is authenticated " + subject.isAuthenticated() + " " + subject.getPrincipals() + " " + rateCounter);


        }
        catch(Exception e)
        {
            e.printStackTrace();
        }



        TaskUtil.defaultTaskScheduler().queue(0, ()->{
            Subject sub = SecurityUtils.getSubject();
            SecurityManager sm =SecurityUtils.getSecurityManager();
            log.getLogger().info("Subject : " + sub.getPrincipals() + " "  +sm);
            //org.apache.shiro.web.mgt.DefaultWebSecurityManager f;
        });

        TaskUtil.waitIfBusy(50);
        System.exit(0);
    }

}
