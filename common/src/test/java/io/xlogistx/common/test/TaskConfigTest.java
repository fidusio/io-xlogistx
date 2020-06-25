package io.xlogistx.common.test;

import io.xlogistx.common.TaskConfig;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.http.HTTPCall;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.util.GSONUtil;

import java.io.IOException;

public class TaskConfigTest {

    TaskConfig tc;
    @BeforeAll
    public void loadConfig() throws IOException {
        String json = IOUtil.inputStreamToString(getClass().getResourceAsStream("/TaskConfig.json"), true);
        tc = GSONUtil.fromJSON(json, TaskConfig.class);
    }


}
