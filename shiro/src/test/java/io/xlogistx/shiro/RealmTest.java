package io.xlogistx.shiro;

import io.xlogistx.shiro.authc.DomainUsernamePasswordToken;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.env.BasicIniEnvironment;
import org.apache.shiro.env.Environment;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.security.HashUtil;
import org.zoxweb.shared.security.SubjectIdentifier;
import org.zoxweb.shared.security.model.SecurityModel;
import org.zoxweb.shared.security.shiro.ShiroRealmStore;
import org.zoxweb.shared.util.BaseSubjectID;
import org.zoxweb.shared.util.RateCounter;

import java.io.PrintStream;
import java.util.UUID;

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
        SubjectIdentifier subjectIdentifier = new SubjectIdentifier();
        subjectIdentifier.setSubjectType(BaseSubjectID.SubjectType.USER);
        subjectIdentifier.setSubjectID("root");
        XlogistXShiroRealm realm = ShiroUtil.getRealm(null);
        ShiroRealmStore srs = realm.getShiroRealmStore();
        srs.addSubjectIdentifier(subjectIdentifier);

        srs.addCredentialInfo("root", HashUtil.toBCryptPassword("secret1"));

    }


    @Test
    public void testRole()
    {

    }

    @Test
    public void testPermission()
    {


        String deviceUUID = UUID.randomUUID().toString();
        String[] subjectPermissions ={
                SecurityModel.toSecTok(SecurityModel.APP, SecurityModel.ALL, "toto"),
                SecurityModel.toSecTok(SecurityModel.USER, SecurityModel.ALL, "toto"),
                SecurityModel.toSecTok(SecurityModel.SHARE, SecurityModel.ALL, SecurityModel.RESOURCE),
                SecurityModel.toSecTok(SecurityModel.PERM_READ_RESOURCE, deviceUUID),
                //SecurityModel.toSecTok(SecurityModel.PERM_ADD_PERMISSION),
                "document:read:*",
                "document:write",
                "imitate:animal:lion,jaguar"
        };



        String[] permissionsToTest = {
                "app:delete:toto",
                "app:update:toto",
                "app:create:titi",
                SecurityModel.toSecTok(SecurityModel.PERM_READ_RESOURCE, deviceUUID, "port:5"),
                "document:read:man and the sea",
                "imitate:animal:lion",
                "imitate:animal:jaguar",
                "imitate:animal:cat",
                "document:read:*",
                SecurityModel.toSecTok(SecurityModel.PERM_READ_RESOURCE, UUID.randomUUID().toString()),


                SecurityModel.toSecTok(SecurityModel.PERM_ADD_PERMISSION, "app:", "gta"),
                SecurityModel.toSecTok(SecurityModel.PERM_ADD_PERMISSION)
        };


        Subject subject = SecurityUtils.getSubject();
        subject.getSession(true);
        DomainUsernamePasswordToken token =  new DomainUsernamePasswordToken("root", "secret1", false, null, null);
        subject.login(token);








        Subject currentUser = SecurityUtils.getSubject();
        assert subject == currentUser;

        XlogistXShiroRealm realm = ShiroUtil.getRealm(XlogistXShiroRealm.class);
        // Create a new AuthorizationInfo instance
        SimpleAuthorizationInfo authorizationInfo = (SimpleAuthorizationInfo) realm.lookupAuthorizationInfo(subject.getPrincipals());
        System.out.println("authorization Info " + authorizationInfo);
        // Add roles
        authorizationInfo.addRole("admin");
        authorizationInfo.addRole("user");
        for(String permission : subjectPermissions) {
            authorizationInfo.addStringPermission(permission);
            System.out.println(permission + " added to " + subject.getPrincipal());
        }
        // Add permissions


        System.out.println(currentUser.getSession().getAttributeKeys());

        // Programmatically set the authorization info for the subject
        // This part assumes you have some way of setting this information
        // on the subject, possibly through a custom realm or a session attribute
        currentUser.getSession().setAttribute("authorizationInfo", authorizationInfo);

        subject.login(token);

        // Check if the current subject has a specific role or permission
        if (currentUser.hasRole("admin")) {
            System.out.println("User has admin role");
        }

        if (currentUser.isPermitted("document:write")) {
            System.out.println("User has permission to write documents");
        }

        RateCounter rc = new RateCounter("permissionRC");
        long ts;
        for(String permission : permissionsToTest)
        {
            ts = System.currentTimeMillis();
            boolean result = subject.isPermitted(permission);
            rc.registerTimeStamp(ts);

            PrintStream ps = result ?  System.out : System.err;
            ps.println(subject.getPrincipal() + " isPermitted  " + result + " permission " + permission + " " + rc);

        }

        subject.logout();
    }


    @Test
    public void testValidLogin()
    {
//        org.apache.shiro.web.servlet.ShiroFilter sf;
        Subject subject = SecurityUtils.getSubject();
        subject.getSession(true);
        DomainUsernamePasswordToken token =  new DomainUsernamePasswordToken("root", "secret1", false, null, null);
        subject.login(token);
        System.out.println("SessionID: " + subject.getSession().getId());
        System.out.println("Principal: " +subject.getPrincipal());
        DefaultSecurityManager dms;
        System.out.println("SecurityManager: " + SecurityUtils.getSecurityManager().getClass());

        System.out.println("before logout: " + subject.getSession().getId());
        System.out.println("Session class : " + subject.getSession().getClass());
        subject.logout();
        System.out.println("after logout: " + subject.getSession().getId());
    }

    @Test
    public void testInvalidLogin()
    {
        Subject subject = SecurityUtils.getSubject();
        DomainUsernamePasswordToken token =  new DomainUsernamePasswordToken("root", "secret12", false, null, null);
        assertThrows(IncorrectCredentialsException.class, ()->{
            subject.login(token);
        });
        System.out.println(subject.getPrincipal());
        subject.logout();
    }


}
