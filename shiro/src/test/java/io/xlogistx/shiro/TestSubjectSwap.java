package io.xlogistx.shiro;

import io.xlogistx.shiro.authc.DomainUsernamePasswordToken;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.logging.LoggerUtil;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.security.HashUtil;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.crypto.PasswordDAO;
import org.zoxweb.shared.security.SubjectIdentifier;
import org.zoxweb.shared.security.shiro.ShiroRealmStore;
import org.zoxweb.shared.util.*;

import java.security.NoSuchAlgorithmException;
import java.util.concurrent.atomic.AtomicInteger;

public class TestSubjectSwap {





    public static NVGenericMap toSubject(Subject subject)
    {
        NVGenericMap nvgm = new NVGenericMap();
        nvgm.add("SubjectRef", ""+subject);
        nvgm.add("Principal", ""+subject.getPrincipal());
        nvgm.add(new NVBoolean("Authenticated", subject.isAuthenticated()));
        nvgm.add("SessionID", ""+subject.getSession().getId());
        nvgm.add(new NVBoolean("IsMainThread", TaskUtil.isMainThread()));
        log.getLogger().info(GSONUtil.toJSONDefault(nvgm, true));
        return nvgm;
    }

    public static LogWrapper log = new LogWrapper(TestSubjectSwap.class).setEnabled(true);
    static Subject testSubjectLogin(int count, String username, String password)
    {
        Subject testSubject = SecurityUtils.getSubject();
        log.getLogger().info("Step: " + count + " " + testSubject + " "  + testSubject.getPrincipal() + " " + testSubject.isAuthenticated());
        testSubject.getSession(true);
        DomainUsernamePasswordToken token =  new DomainUsernamePasswordToken(username, password, false, null, null);
        testSubject.login(token);
        toSubject(testSubject);
        log.getLogger().info( "\n");

        return testSubject;
    }

    private static Subject mainSubject;


    private static void domainSubjectSetup() throws NoSuchAlgorithmException {
        TaskUtil.registerMainThread();
        //org.apache.shiro.web.servlet.ShiroFilter
        SecurityManager securityManager = ShiroUtil.loadSecurityManager("classpath:shiro-xlog.ini");

//        Environment env = new BasicIniEnvironment("classpath:shiro-xlog.ini");
//        SecurityManager securityManager = env.getSecurityManager();
        System.out.println(securityManager.getClass().getName());
        SecurityUtils.setSecurityManager(securityManager);

        SubjectIdentifier subjectIDDAO = new SubjectIdentifier();
        subjectIDDAO.setSubjectType(BaseSubjectID.SubjectType.USER);
        subjectIDDAO.setSubjectID("root");
        XlogistXShiroRealm realm = ShiroUtil.getRealm(null);
        ShiroRealmStore srs = realm.getShiroRealmStore();
        srs.addSubjectIdentifier(subjectIDDAO);
        PasswordDAO rootPasswordDAO = HashUtil.toBCryptPassword("secret1");
        String bcryptedPassword = rootPasswordDAO.toCanonicalID();
        log.getLogger().info(bcryptedPassword);
        srs.addCredentialInfo("root", PasswordDAO.fromCanonicalID(bcryptedPassword));



        subjectIDDAO = new SubjectIdentifier();
        subjectIDDAO.setSubjectType(BaseSubjectID.SubjectType.USER);
        subjectIDDAO.setSubjectID("mario");
        srs.addSubjectIdentifier(subjectIDDAO);
        srs.addCredentialInfo("mario", "password1");

        subjectIDDAO = new SubjectIdentifier();
        subjectIDDAO.setSubjectType(BaseSubjectID.SubjectType.USER);
        subjectIDDAO.setSubjectID("toSwapWith");
        srs.addSubjectIdentifier(subjectIDDAO);
        srs.addCredentialInfo("toSwapWith", "batata1");
    }


    public static void main(final String ...args)
    {
        try {


            LoggerUtil.enableDefaultLogger("io.xlogistx");
            domainSubjectSetup();
            RateCounter rc = new RateCounter("shiro");
            AtomicInteger counter = new AtomicInteger();
            long startTime = System.currentTimeMillis();


            // this is a trick to create a subject like super user or admin outside the scope of the main thread and the taskutil thread pools
            Thread t = new Thread(() -> {
                mainSubject = testSubjectLogin(counter.incrementAndGet(), "toSwapWith", "batata1");
            });
            t.start();
            try {
                t.join();
                log.info("The temporary thread is dead status: " + t.isAlive());
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

            ///


            final ThreadLocal<Integer> tli = ThreadLocal.withInitial(Integer.valueOf(0)::intValue);
            TaskUtil.defaultTaskScheduler().queue(0, () -> {
                testSubjectLogin(counter.incrementAndGet(), "root", "secret1");


            });
            TaskUtil.waitIfBusy(50);


            TaskUtil.defaultTaskScheduler().queue(0, () -> {
                testSubjectLogin(counter.incrementAndGet(), "marwan", "password1");
                SubjectSwap ss = new SubjectSwap(mainSubject);
                log.getLogger().info("++++++++++++++++++++++++++++++++++++++++++");
                toSubject(SecurityUtils.getSubject());
                ss.close();
                log.getLogger().info("------------------------------------------");
                toSubject(SecurityUtils.getSubject());
            });


            TaskUtil.waitIfBusy(50);

            for (int i = 0; i < TaskUtil.defaultTaskProcessor().workersThreadCapacity() * 2; i++) {
                TaskUtil.defaultTaskProcessor().execute(() -> {
                    System.out.println(Thread.currentThread() + " Should be null: " + (0 == tli.get()) + " " + tli.get());

                    tli.set(counter.incrementAndGet());
                    System.out.println(Thread.currentThread() + " Counter value : " + tli.get() + " " + tli.hashCode());
                    tli.remove();

                    Subject testSubject = SecurityUtils.getSubject();
                    if (testSubject.isAuthenticated()) {
                        log.getLogger().info("Session found " + testSubject.getSession().getId());
                    }
                });
            }


            System.out.println("Wait if busy return: " + TaskUtil.waitIfBusy(10));

            System.out.println("Thread count: " + TaskUtil.defaultTaskProcessor().workersThreadCapacity());
            TaskUtil.close();
            System.out.println("After TaskUtil.close()");
            rc.registerTimeStamp(startTime);
            System.out.println(rc);

            System.out.println("SecurityManager type: " + SecurityUtils.getSecurityManager().getClass());


            try {
                SecurityUtils.getSubject();
            } catch (Exception e) {
                e.printStackTrace();
            }


            try {
                SecurityUtils.getSubject();
            } catch (Exception e) {
                e.printStackTrace();
            }

            try {
                log.getLogger().info("" + GSONUtil.toJSONDefault(HashUtil.toPassword(CryptoConst.HASHType.BCRYPT, 0, 10, "D!v2c3$Dm5n")));

                String data = "GET" + "/data" + "Mon, 25 Jul 2023 05:00:00 GMT";
                String secret = "mysecretkey123";
                byte[] hmac = CryptoUtil.hmacSHA256(SharedStringUtil.getBytes(secret), SharedStringUtil.getBytes(data));
                System.out.println(SharedStringUtil.bytesToHex(hmac));

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }

    }
}
