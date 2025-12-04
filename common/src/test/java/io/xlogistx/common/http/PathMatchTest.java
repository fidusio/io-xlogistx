package io.xlogistx.common.http;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Paths;

public class PathMatchTest {

    @Test
    public void positive() throws IOException {
        CachedPathMatcher pm = new CachedPathMatcher();




        System.out.println(pm.findIn(Paths.get("/webs/xlogistx.io"), "/articles/NIOFramework"));
        System.out.println(pm.findIn(Paths.get("/webs/xlogistx.io"), "/articles/NIOFramework"));
        System.out.println(pm.findIn(Paths.get("/webs/xlogistx.io"), "/articles/nioFramework/MultiThreadNIOssLSocket.html"));

        System.out.println(pm.findIn(Paths.get("/webs/xlogistx.io"), "Index.ht"));
    }
}
