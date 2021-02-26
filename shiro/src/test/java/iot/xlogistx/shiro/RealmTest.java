package iot.xlogistx.shiro;

import io.xlogistx.shiro.ShiroUtil;
import io.xlogistx.shiro.XlogistXShiroRealm;
import io.xlogistx.shiro.authc.DomainUsernamePasswordToken;
import org.apache.shiro.SecurityUtils;

import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.env.BasicIniEnvironment;
import org.apache.shiro.env.Environment;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zoxweb.shared.security.SubjectIDDAO;
import org.zoxweb.shared.security.shiro.ShiroRealmStore;
import org.zoxweb.shared.util.BaseSubjectID;

import static org.junit.jupiter.api.Assertions.assertThrows;


public class RealmTest {



    @BeforeAll
    public static void loadRealm()
    {
        Environment env = new BasicIniEnvironment("classpath:shiro-xlog.ini");
        SecurityManager securityManager = env.getSecurityManager();
        System.out.println(securityManager.getClass().getName());
        SecurityUtils.setSecurityManager(securityManager);
        Subject subject = SecurityUtils.getSubject();
        SubjectIDDAO subjectIDDAO = new SubjectIDDAO();
        subjectIDDAO.setSubjectType(BaseSubjectID.SubjectType.USER);
        subjectIDDAO.setSubjectID("root");
        XlogistXShiroRealm realm = ShiroUtil.getRealm(null);
        ShiroRealmStore srs = realm.getShiroRealmStore();
        srs.addSubject(subjectIDDAO);
        srs.setSubjectPassword("root", "secret");
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
    public void testValidLogin()
    {
        Subject subject = SecurityUtils.getSubject();
        DomainUsernamePasswordToken token =  new DomainUsernamePasswordToken("root", "secret", false, null, null);
        subject.login(token);
        System.out.println(subject.getPrincipal());
        subject.logout();
    }

    @Test
    public void testInvalidLogin()
    {
        Subject subject = SecurityUtils.getSubject();
        DomainUsernamePasswordToken token =  new DomainUsernamePasswordToken("root", "secret1", false, null, null);
        assertThrows(IncorrectCredentialsException.class, ()->{
            subject.login(token);
        });
        System.out.println(subject.getPrincipal());
        subject.logout();
    }


}
