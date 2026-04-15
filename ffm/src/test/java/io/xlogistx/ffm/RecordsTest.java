package io.xlogistx.ffm;

import org.junit.jupiter.api.Test;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.util.SUS;

public class RecordsTest {

    public record Data(String name, String description, int grade){

    }



    @Test
    public void testRecordSimple()
    {
        Data rec = new Data("mufassa", "lion king", 20);
        System.out.println(rec);
        System.out.println(SUS.toCanonicalID(',', rec.name, rec.description, rec.grade));
    }

    @Test
    public void testRecordToJSON()
    {
        Data rec = new Data("json", "bourne", 100);
        String json = GSONUtil.toJSONDefault(rec);
        System.out.println(json);
        Data rec2 = GSONUtil.fromJSONDefault(json, Data.class);
        System.out.println(SUS.toCanonicalID(',', rec2.name, rec2.description, rec2.grade));
        assert rec2.equals(rec);
    }

}
