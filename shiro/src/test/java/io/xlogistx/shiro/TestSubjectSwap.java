package io.xlogistx.shiro;

import io.xlogistx.shiro.authc.DomainUsernamePasswordToken;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.env.BasicIniEnvironment;
import org.apache.shiro.env.Environment;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.logging.LoggerUtil;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.security.SubjectIDDAO;
import org.zoxweb.shared.security.shiro.ShiroRealmStore;
import org.zoxweb.shared.util.BaseSubjectID;
import org.zoxweb.shared.util.RateCounter;

import java.util.concurrent.atomic.AtomicInteger;

public class TestSubjectSwap {



    public static LogWrapper log = new LogWrapper(TestSubjectSwap.class).setEnabled(true);
    static void testSubjectLogin(int count, String username, String password)
    {
        Subject testSubject = SecurityUtils.getSubject();
        log.getLogger().info("Step: " + count + " " + testSubject + " "  + testSubject.getPrincipal() + " " + testSubject.isAuthenticated());
        testSubject.getSession(true);
        DomainUsernamePasswordToken token =  new DomainUsernamePasswordToken(username, password, false, null, null);
        testSubject.login(token);
        log.getLogger().info("Principal: " + testSubject.getPrincipal() + " SessionID: " + testSubject.getSession().getId() + "\n ");
    }

    public static void main(final String ...args)
    {
        LoggerUtil.enableDefaultLogger("io.xlogistx");
        //org.apache.shiro.web.servlet.ShiroFilter
        RateCounter rc = new RateCounter("shiro");
        long startTime = System.currentTimeMillis();
        Environment env = new BasicIniEnvironment("classpath:shiro-xlog.ini");
        SecurityManager securityManager = env.getSecurityManager();
        System.out.println(securityManager.getClass().getName());
        SecurityUtils.setSecurityManager(securityManager);

        SubjectIDDAO subjectIDDAO = new SubjectIDDAO();
        subjectIDDAO.setSubjectType(BaseSubjectID.SubjectType.USER);
        subjectIDDAO.setSubjectID("root");
        XlogistXShiroRealm realm = ShiroUtil.getRealm(null);
        ShiroRealmStore srs = realm.getShiroRealmStore();
        srs.addSubject(subjectIDDAO);
        srs.setSubjectPassword("root", "secret1");



        subjectIDDAO = new SubjectIDDAO();
        subjectIDDAO.setSubjectType(BaseSubjectID.SubjectType.USER);
        subjectIDDAO.setSubjectID("marwan");
        srs.addSubject(subjectIDDAO);
        srs.setSubjectPassword("marwan", "password1");

        final AtomicInteger counter = new AtomicInteger();
        final ThreadLocal<Integer> tli = ThreadLocal.withInitial(Integer.valueOf(0)::intValue);
        TaskUtil.getDefaultTaskScheduler().queue(0, ()->{
            testSubjectLogin(counter.incrementAndGet(), "root", "secret1");
        });
        TaskUtil.waitIfBusy(50);


        TaskUtil.getDefaultTaskScheduler().queue(0, ()->{
            testSubjectLogin(counter.incrementAndGet(), "marwan", "password1");
        });


        TaskUtil.waitIfBusy(50);


//        for(int i = 0; i < TaskUtil.getDefaultTaskProcessor().workersThreadCapacity()*2; i++)
//        {
//            TaskUtil.getDefaultTaskProcessor().execute(()->{
//                System.out.println(Thread.currentThread() + " Should be null: " +  (0 == tli.get()) + " " + tli.get());
//
//                tli.set(counter.incrementAndGet());
//                System.out.println(Thread.currentThread() + " Counter value : " + tli.get() + " " + tli.hashCode());
//                //tli.remove();
//            });
//        }


        System.out.println("Wait if busy return: " + TaskUtil.waitIfBusy(10));

        System.out.println("Thread count: " + TaskUtil.getDefaultTaskProcessor().workersThreadCapacity());
        TaskUtil.close();
        System.out.println("After TaskUtil.close()");
        rc.registerTimeStamp(startTime);
        System.out.println(rc);

        System.out.println("SecurityManager type: " + SecurityUtils.getSecurityManager().getClass());
    }
}
