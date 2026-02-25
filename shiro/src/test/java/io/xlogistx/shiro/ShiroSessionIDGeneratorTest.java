package io.xlogistx.shiro;

import io.xlogistx.shiro.mgt.ShiroSessionIDGenerator;
import org.apache.shiro.session.mgt.eis.JavaUuidSessionIdGenerator;
import org.apache.shiro.session.mgt.eis.SessionIdGenerator;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.util.RateCounter;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

public class ShiroSessionIDGeneratorTest
{
    public static final LogWrapper log = new LogWrapper(ShiroSessionIDGeneratorTest.class).setEnabled(true);

    public static void main(String... args)
    {
        try
        {
            int iterations = args.length > 0 ? Integer.parseInt(args[0]) : 100_000;

            ShiroSessionIDGenerator secureGen =  new ShiroSessionIDGenerator();
            JavaUuidSessionIdGenerator uuidGen = new JavaUuidSessionIdGenerator();

            // Test 1: Basic generation and format validation
            log.getLogger().info("=== Test 1: Format Validation ===");
            Serializable id = secureGen.generateId(null);
            String idStr = id.toString();
            log.getLogger().info("Generated ID: " + idStr);
            log.getLogger().info("Length: " + idStr.length() + " (expected 64)");
            assert idStr.length() == 64 : "Expected 64 hex chars for 256-bit ID, got " + idStr.length();
            assert idStr.matches("[0-9a-f]+") : "ID should be lowercase hex only";
            log.getLogger().info("Format validation PASSED");

            // Test 2: Uniqueness check
            log.getLogger().info("=== Test 2: Uniqueness (" + iterations + " IDs) ===");
            Set<Serializable> ids = new HashSet<>();
            for (int i = 0; i < iterations; i++)
            {
                boolean added = ids.add(secureGen.generateId(null));
                assert added : "Duplicate ID detected at iteration " + i;
            }
            log.getLogger().info("Uniqueness PASSED - " + iterations + " unique IDs generated");

            // Test 3: Speed comparison
            log.getLogger().info("=== Test 3: Speed Comparison (" + iterations + " iterations) ===");

            // Warmup both generators
            benchmark(secureGen, 10_000);
            benchmark(uuidGen, 10_000);

            // Benchmark ShiroSessionIDGenerator (SecureRandom 256-bit)
            RateCounter secureCounter = benchmark(secureGen, iterations);
            log.getLogger().info("ShiroSessionIDGenerator (SecureRandom 256-bit): " + secureCounter);

            // Benchmark JavaUuidSessionIdGenerator (UUID)
            RateCounter uuidCounter = benchmark(uuidGen, iterations);
            log.getLogger().info("JavaUuidSessionIdGenerator (UUID):              " + uuidCounter);

            log.getLogger().info("=== All tests PASSED ===");
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    private static RateCounter benchmark(SessionIdGenerator generator, int iterations)
    {
        RateCounter counter = new RateCounter(generator.getClass().getSimpleName());
        long timestamp = System.currentTimeMillis();
        for (int i = 0; i < iterations; i++)
        {
            generator.generateId(null);
            timestamp = counter.registerTimeStamp(timestamp);
        }
        return counter;
    }
}
