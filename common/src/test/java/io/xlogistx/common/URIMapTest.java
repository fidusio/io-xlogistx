package io.xlogistx.common;


import io.xlogistx.common.http.URIMap;
import org.junit.jupiter.api.Test;
import org.zoxweb.shared.filters.MatchPatternFilter;
import org.zoxweb.shared.util.Const;

import java.util.Arrays;


public class URIMapTest {


    @Test
    public void uriPatterTest()
    {



        try
        {
            String[] uris = {"/potato", "/potato/sweet", "/batikh", "/batikh/masmar", "/"};
            String[] tokens= {"/potato", "/potato?a=b", "/potato/pototo", "/a/*","/potato/sweet/red", "/potato/boiled", "/not-found/at-all", "/potato/potato/potato/potato/potato/potato/potato/potato/potato/potato/potato/potato/potato/potato/potato/potato/potato/potato/potato/potato/potato/potato/potato/potato/", "/"};
            MatchPatternFilter filter = MatchPatternFilter.createMatchFilter("-i", "/*");

           URIMap<String> uriMap = new URIMap<>();
            for(String uri : uris)
            {
                uriMap.put(uri, uri);

            }
            int loops = 10;
            for(int i = 0; i < 10; i++)
                for (String token : tokens)
                {
                    long ts = System.nanoTime();
                    String m = uriMap.lookup(token);
                    ts = System.nanoTime() - ts;

                    if(i == loops-1)
                        System.out.println(filter.match(URIMap.normalize(token)) + " Token: " + token + ", match: " + m + " it took: " + Const.TimeInMillis.nanosToString(ts))  ;
                }

            System.out.println("size: " + uriMap.size());
            System.out.println(Arrays.toString(filter.getMatchPatterns()));

        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }
}
