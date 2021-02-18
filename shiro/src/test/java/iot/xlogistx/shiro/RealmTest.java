package iot.xlogistx.shiro;

import io.xlogistx.shiro.ShiroUtil;
import io.xlogistx.shiro.XlogistXShiroRealm;
import io.xlogistx.shiro.authc.DomainUsernamePasswordToken;
import org.apache.shiro.SecurityUtils;

import org.apache.shiro.env.BasicIniEnvironment;
import org.apache.shiro.env.Environment;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zoxweb.shared.security.SubjectIDDAO;
import org.zoxweb.shared.security.shiro.ShiroRealmStore;
import org.zoxweb.shared.util.BaseSubjectID;


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
        SubjectIDDAO subjectIDDAO = new SubjectIDDAO();
        subjectIDDAO.setSubjectType(BaseSubjectID.SubjectType.USER);
        subjectIDDAO.setSubjectID("root");
        XlogistXShiroRealm realm = ShiroUtil.getRealm(null);


        ShiroRealmStore srs = realm.getShiroRealmStore();//ResourceManager.SINGLETON.lookup(ResourceManager.Resource.REALM_STORE);
        srs.setSubjectPassword("root", "secret");

        srs.addSubject(subjectIDDAO);
        DomainUsernamePasswordToken token =  new DomainUsernamePasswordToken("root", "secret", false, null, null);
        subject.login(token);
        System.out.println(subject.getPrincipal());
    }


}
