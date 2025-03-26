package io.xlogistx.common.http;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NVStringList;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.util.Arrays;
import java.util.List;

public class WebSocketAnnotationsTest {

    public static final String ANNOT_CONFIG = "ws-annotations-param.json";
    private static NVGenericMap annotConfig = null;
    @BeforeAll
    public static void load() throws IOException {
        annotConfig = GSONUtil.fromJSONDefault(IOUtil.inputStreamToString(IOUtil.locateFile(ANNOT_CONFIG)), NVGenericMap.class);

    }


    @Test
    public void convertAnnotations() throws ClassNotFoundException {

        for(NVGenericMap annotProp : annotConfig.valuesAs(new NVGenericMap[0]))
        {
            System.out.println(annotProp.getName());
            String annotType = annotProp.getValue("annotation-type");
            Class<?extends Annotation> annotClass = (Class<? extends Annotation>) Class.forName(annotType);
            System.out.println("AnnotationType: " + annotClass);

            List<NVGenericMap> paramsConfig = annotProp.getValue("params");

            for(NVGenericMap paramConfig : paramsConfig)
            {
                boolean isMandatory = paramConfig.getValue("mandatory");
                int count = paramConfig.getValue("count");
                NVStringList typeClassNames = paramConfig.getNV("types");

                String[] classTypeNames = typeClassNames.getValues();
                Class<?>[] types = new Class<?>[classTypeNames.length];
                for (int i = 0; i < types.length; i++)
                {
                    types[i] = Class.forName(classTypeNames[i]);
                }
                System.out.println("isMandatory: " + isMandatory + " count: " + count + " ClassTypes: " + Arrays.toString(types));

            }

        }
    }


}
