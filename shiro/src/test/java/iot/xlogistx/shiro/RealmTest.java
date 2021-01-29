package iot.xlogistx.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.env.BasicIniEnvironment;
import org.apache.shiro.env.Environment;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class RealmTest {
    @BeforeAll
    public static void loadRealm()
    {
    }


    @Test
    public void testRole()
    {

    }

    @Test
    public void testPermission()
    {

    }

    @Test
    public void testIniLoading()
    {
//        Environment env = new BasicIniEnvironment("classpath:shiro.ini");
//        SecurityManager securityManager = env.getSecurityManager();
//        SecurityUtils.setSecurityManager(securityManager);
//        Subject subject = SecurityUtils.getSubject();
//        UsernamePasswordToken token =  new UsernamePasswordToken("root", "secret");
//        subject.login(token);
//        System.out.println(subject.getPrincipal());
    }

    @Test
    public void testXlogIniLoading()
    {
        Environment env = new BasicIniEnvironment("classpath:shiro-xlog.ini");
        SecurityManager securityManager = env.getSecurityManager();
        System.out.println(securityManager.getClass().getName());
        SecurityUtils.setSecurityManager(securityManager);
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token =  new UsernamePasswordToken("root", "secret");
        subject.login(token);
        System.out.println(subject.getPrincipal());
    }


}
