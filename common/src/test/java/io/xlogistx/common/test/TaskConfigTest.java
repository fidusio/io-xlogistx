package io.xlogistx.common.test;

import io.xlogistx.common.TaskConfig;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.util.GSONUtil;

import java.io.IOException;

public class TaskConfigTest {

    static TaskConfig tc;
    @BeforeAll
    public static void loadConfig() throws IOException {
        String json = IOUtil.inputStreamToString(TaskConfigTest.class.getResourceAsStream("/TaskConfig.json"), true);
        tc = GSONUtil.fromJSON(json, TaskConfig.class);
    }

    @Test
    public void Test()
    {

    }


}
