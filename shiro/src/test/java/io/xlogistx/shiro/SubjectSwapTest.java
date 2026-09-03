package io.xlogistx.shiro;

import io.xlogistx.shiro.authc.DomainUsernamePasswordToken;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.config.Ini;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Programmatic test for {@link SubjectSwap}: the security manager and its realm are
 * built in code (no ini file, no data store) so the swap semantics can be asserted
 * deterministically on the calling thread, on foreign threads and on pooled threads.
 */
public class SubjectSwapTest {

    private static final String ROOT = "root";
    private static final String ROOT_PASSWORD = "secret1";
    private static final String MARIO = "mario";
    private static final String MARIO_PASSWORD = "password1";
    private static final String SWAP_USER = "toswapwith";
    private static final String SWAP_PASSWORD = "batata1";

    private static SecurityManager securityManager;

    @BeforeAll
    static void setupSecurityManager() {
        Ini ini = new Ini();
        ini.setSectionProperty(IniRealm.USERS_SECTION_NAME, ROOT, ROOT_PASSWORD + ", admin");
        ini.setSectionProperty(IniRealm.USERS_SECTION_NAME, MARIO, MARIO_PASSWORD + ", user");
        ini.setSectionProperty(IniRealm.USERS_SECTION_NAME, SWAP_USER, SWAP_PASSWORD + ", admin");
        ini.setSectionProperty(IniRealm.ROLES_SECTION_NAME, "admin", "*");
        ini.setSectionProperty(IniRealm.ROLES_SECTION_NAME, "user", "user:read");

        XlogistXIniRealm realm = new XlogistXIniRealm();
        realm.setIni(ini);
        realm.init();

        securityManager = new DefaultSecurityManager(realm);
        SecurityUtils.setSecurityManager(securityManager);
    }

    @AfterAll
    static void tearDownSecurityManager() {
        ThreadContext.remove();
        SecurityUtils.setSecurityManager(null);
    }

    @BeforeEach
    @AfterEach
    void clearThreadContext() {
        ThreadContext.remove();
    }

    // ---------------------------------------------------------------- helpers

    private static Subject login(String username, String password) {
        Subject subject = SecurityUtils.getSubject();
        subject.login(new DomainUsernamePasswordToken(username, password, false, null, null));
        assertTrue(subject.isAuthenticated(), "login failed for " + username);
        return subject;
    }

    /** Logs in on a throw-away thread so the returned subject is not bound to the calling thread. */
    private static Subject loginOnForeignThread(String username, String password) throws Exception {
        return onForeignThread(() -> {
            try {
                return login(username, password);
            } finally {
                ThreadContext.remove();
            }
        });
    }

    private static <T> T onForeignThread(Callable<T> task) throws Exception {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            return executor.submit(task).get(10, TimeUnit.SECONDS);
        } finally {
            executor.shutdownNow();
        }
    }

    // ------------------------------------------------------------------ tests

    @Test
    void swapReplacesCurrentSubjectAndCloseRestoresIt() throws Exception {
        Subject swapSubject = loginOnForeignThread(SWAP_USER, SWAP_PASSWORD);
        Subject current = login(MARIO, MARIO_PASSWORD);
        assertNotSame(swapSubject, current);

        try (SubjectSwap ignored = new SubjectSwap(swapSubject)) {
            Subject swapped = SecurityUtils.getSubject();
            assertSame(swapSubject, swapped);
            assertEquals(SWAP_USER, swapped.getPrincipal());
            assertTrue(swapped.hasRole("admin"));
            assertTrue(swapped.isPermitted("anything:goes"));
            assertEquals(swapSubject.getSession().getId(), swapped.getSession().getId());
        }

        Subject restored = SecurityUtils.getSubject();
        assertSame(current, restored);
        assertEquals(MARIO, restored.getPrincipal());
        assertTrue(restored.hasRole("user"));
        assertFalse(restored.isPermitted("anything:goes"));
    }

    @Test
    void nullSwapIsNoOp() {
        Subject current = login(MARIO, MARIO_PASSWORD);
        try (SubjectSwap ignored = new SubjectSwap(null)) {
            assertSame(current, SecurityUtils.getSubject());
        }
        assertSame(current, SecurityUtils.getSubject());
    }

    @Test
    void swapOnThreadWithNoSubjectLeavesThreadUnboundAfterClose() throws Exception {
        Subject swapSubject = loginOnForeignThread(SWAP_USER, SWAP_PASSWORD);

        Boolean result = onForeignThread(() -> {
            assertNull(ThreadContext.getSubject(), "fresh thread must start unbound");
            try (SubjectSwap ignored = new SubjectSwap(swapSubject)) {
                assertSame(swapSubject, SecurityUtils.getSubject());
                assertEquals(SWAP_USER, SecurityUtils.getSubject().getPrincipal());
            }
            assertNull(ThreadContext.getSubject(), "close must not leave a subject bound");
            Subject anonymous = SecurityUtils.getSubject();
            assertFalse(anonymous.isAuthenticated());
            assertNull(anonymous.getPrincipal());
            return Boolean.TRUE;
        });
        assertTrue(result);
    }

    @Test
    void nestedSwapsRestoreInLifoOrder() throws Exception {
        Subject rootSubject = loginOnForeignThread(ROOT, ROOT_PASSWORD);
        Subject swapSubject = loginOnForeignThread(SWAP_USER, SWAP_PASSWORD);
        Subject current = login(MARIO, MARIO_PASSWORD);

        try (SubjectSwap outer = new SubjectSwap(rootSubject)) {
            assertEquals(ROOT, SecurityUtils.getSubject().getPrincipal());
            try (SubjectSwap inner = new SubjectSwap(swapSubject)) {
                assertEquals(SWAP_USER, SecurityUtils.getSubject().getPrincipal());
            }
            assertSame(rootSubject, SecurityUtils.getSubject());
            assertEquals(ROOT, SecurityUtils.getSubject().getPrincipal());
        }
        assertSame(current, SecurityUtils.getSubject());
        assertEquals(MARIO, SecurityUtils.getSubject().getPrincipal());
    }

    @Test
    void closeIsIdempotent() throws Exception {
        Subject swapSubject = loginOnForeignThread(SWAP_USER, SWAP_PASSWORD);
        Subject current = login(MARIO, MARIO_PASSWORD);

        SubjectSwap swap = new SubjectSwap(swapSubject);
        assertSame(swapSubject, SecurityUtils.getSubject());
        swap.close();
        assertSame(current, SecurityUtils.getSubject());
        swap.close();
        assertSame(current, SecurityUtils.getSubject());
    }

    /**
     * Shiro's ThreadContext is an InheritableThreadLocal: a thread that already exists
     * when the swap happens never sees it, but a thread spawned while the swap is active
     * inherits a copy of the swapped subject.
     */
    @Test
    void swapIsInvisibleToExistingThreadsButInheritedBySpawnedThreads() throws Exception {
        // Force the worker thread into existence before anything is bound on this thread,
        // so it inherits no subject at all.
        ExecutorService existing = Executors.newSingleThreadExecutor();
        try {
            existing.submit(() -> null).get(10, TimeUnit.SECONDS);

            Subject swapSubject = loginOnForeignThread(SWAP_USER, SWAP_PASSWORD);
            login(MARIO, MARIO_PASSWORD);

            try (SubjectSwap ignored = new SubjectSwap(swapSubject)) {
                assertEquals(SWAP_USER, SecurityUtils.getSubject().getPrincipal());

                Object existingThreadPrincipal = existing.submit(() -> {
                    assertNull(ThreadContext.getSubject(), "pre-existing thread must not see the swap");
                    return SecurityUtils.getSubject().getPrincipal();
                }).get(10, TimeUnit.SECONDS);
                assertNull(existingThreadPrincipal);

                Object spawnedThreadPrincipal = onForeignThread(() -> SecurityUtils.getSubject().getPrincipal());
                assertEquals(SWAP_USER, spawnedThreadPrincipal, "thread spawned during the swap inherits it");
            }
        } finally {
            existing.shutdownNow();
        }
    }

    @Test
    void swapOnPooledThreadsRestoresEveryWorker() throws Exception {
        Subject swapSubject = loginOnForeignThread(SWAP_USER, SWAP_PASSWORD);
        int workers = 4;
        int tasks = workers * 8;
        ExecutorService pool = Executors.newFixedThreadPool(workers);
        try {
            List<Future<Boolean>> results = new ArrayList<>();
            for (int i = 0; i < tasks; i++) {
                results.add(pool.submit(() -> {
                    assertNull(ThreadContext.getSubject(), "worker must start each task unbound");
                    try (SubjectSwap ignored = new SubjectSwap(swapSubject)) {
                        assertSame(swapSubject, SecurityUtils.getSubject());
                        assertTrue(SecurityUtils.getSubject().isPermitted("pool:task"));
                    }
                    assertNull(ThreadContext.getSubject(), "worker must be unbound after close");
                    return Boolean.TRUE;
                }));
            }
            for (Future<Boolean> f : results) {
                assertTrue(f.get(10, TimeUnit.SECONDS));
            }
        } finally {
            pool.shutdownNow();
            assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        }
    }
}
