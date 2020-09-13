package io.xlogistx.common.test.util;

import io.xlogistx.common.cron.CronConfig;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.util.GSONUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Arrays;

public class CronConfigTest {

    @Test
    public void configTest() throws IOException {
        File file = IOUtil.locateFile("cron_config.json");
        System.out.println("File:" + file);
        String json = IOUtil.inputStreamToString(new FileInputStream(file), true);
        System.out.println("json: " + json);
        CronConfig cc = GSONUtil.fromJSON(json, CronConfig.class);
        System.out.println(Arrays.toString(cc.getConfigs()));
        System.out.println(cc.getConfigs().getClass().getName());
    }
}
