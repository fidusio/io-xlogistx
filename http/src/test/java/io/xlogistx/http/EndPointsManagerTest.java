package io.xlogistx.http;

import org.junit.jupiter.api.Test;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.http.HTTPServerConfig;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;

public class EndPointsManagerTest {

    @Test
    public void scan() throws IOException {
        File file = IOUtil.locateFile("http_server_config.json");
        System.out.println("File:" + file);
        String json = IOUtil.inputStreamToString(new FileInputStream(file), true);
        HTTPServerConfig hsc = GSONUtil.fromJSON(json, HTTPServerConfig.class);
        EndPointsManager.scan(hsc);
    }
}
