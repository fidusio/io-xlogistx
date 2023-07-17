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
    public static void main(final String ...args)
    {
        LoggerUtil.enableDefaultLogger("io.xlogistx");
        //org.apache.shiro.web.servlet.ShiroFilter
        final RateCounter rc = new RateCounter("shiro");
        final long startTime = System.currentTimeMillis();
        final Environment env = new BasicIniEnvironment("classpath:shiro-xlog.ini");
        final SecurityManager securityManager = env.getSecurityManager();
        System.out.println(securityManager.getClass().getName());
        SecurityUtils.setSecurityManager(securityManager);
        final Subject subject = SecurityUtils.getSubject();
        SubjectIDDAO subjectIDDAO = new SubjectIDDAO();
        subjectIDDAO.setSubjectType(BaseSubjectID.SubjectType.USER);
        subjectIDDAO.setSubjectID("root");
        final XlogistXShiroRealm realm = ShiroUtil.getRealm(null);
        final ShiroRealmStore srs = realm.getShiroRealmStore();
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

            final Subject testSubject = SecurityUtils.getSubject();
            TestSubjectSwap.log.getLogger().info("Step: " + counter.incrementAndGet() + " " + Thread.currentThread() + " " + subject + " "  + subject.getPrincipal());
            testSubject.getSession(true);
            final DomainUsernamePasswordToken token =  new DomainUsernamePasswordToken("root", "secret1", false, null, null);
            testSubject.login(token);
            TestSubjectSwap.log.getLogger().info("SessionID: " + testSubject.getSession().getId() + " "  + Thread.currentThread());
            TestSubjectSwap.log.getLogger().info("Principal: " +testSubject.getPrincipal());

        });
        TaskUtil.waitIfBusy(50);


        TaskUtil.getDefaultTaskScheduler().queue(0, ()->{
            final Subject testSubject = SecurityUtils.getSubject();
            TestSubjectSwap.log.getLogger().info("Step: " + counter.incrementAndGet() + " "+  Thread.currentThread() + " " + subject + " "  + subject.getPrincipal());
            testSubject.getSession(true);
            final DomainUsernamePasswordToken token =  new DomainUsernamePasswordToken("marwan", "password1", false, null, null);
            testSubject.login(token);
            TestSubjectSwap.log.getLogger().info("SessionID: " + testSubject.getSession().getId() + " "  + Thread.currentThread());
            TestSubjectSwap.log.getLogger().info("Principal: " +testSubject.getPrincipal());


        });


        TaskUtil.waitIfBusy(50);


        for(int i = 0; i < TaskUtil.getDefaultTaskProcessor().workersThreadCapacity()*2; i++)
        {
            TaskUtil.getDefaultTaskProcessor().execute(()->{
                System.out.println(Thread.currentThread() + " Should be null: " +  (0 == tli.get()) + " " + tli.get());

                tli.set(counter.incrementAndGet());
                System.out.println(Thread.currentThread() + " Counter value : " + tli.get() + " " + tli.hashCode());
                //tli.remove();
            });
        }


        System.out.println("Wait if busy return: " + TaskUtil.waitIfBusy(10));

        System.out.println("Thread count: " + TaskUtil.getDefaultTaskProcessor().workersThreadCapacity());
        TaskUtil.close();
        System.out.println("After TaskUtil.close()");
        rc.registerTimeStamp(startTime);
        System.out.println(rc);
    }
}
