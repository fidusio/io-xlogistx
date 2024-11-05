package io.xlogistx.http.services;

import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.http.HTTPConst;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.security.model.SecurityModel;
import org.zoxweb.shared.util.*;

import java.util.Arrays;
import java.util.Date;

@SecurityProp(authentications = {CryptoConst.AuthenticationType.ALL})
public class TestEndPoint {

    public static class DataObject
    {
        private String name;
        private int length;

        public String toString()
        {
            return name + ", " + length;
        }
    }

    @EndPointProp(methods = {HTTPMethod.GET}, name="html-test", uris="/html/{testValue}", responseContentType = HTTPConst.TEXT_HTML)
    public String stringAsHTML(@ParamProp(name="testValue", optional = true) String testValue)
    {
        StringBuilder htmlBuilder = new StringBuilder();

        // Start HTML document
        htmlBuilder.append("<!DOCTYPE html>\n");
        htmlBuilder.append("<html>\n");
        htmlBuilder.append("<head>\n");
        htmlBuilder.append("    <title>Example HTML</title>\n");
        htmlBuilder.append("</head>\n");
        htmlBuilder.append("<body>\n");

        // Add content
        htmlBuilder.append("    <h1>Welcome to My Website</h1>\n");
        htmlBuilder.append("    <p>This is a paragraph of text on my website.</p>\n");
        htmlBuilder.append("    <ul>\n");
        htmlBuilder.append("        <li>today date: " + new Date() + "</li>\n");
        if(!SUS.isEmpty(testValue))
            htmlBuilder.append("        <li>user value: " + testValue + "</li>\n");
        htmlBuilder.append("    </ul>\n");

        // End HTML document
        htmlBuilder.append("</body>\n");
        htmlBuilder.append("</html>\n");

        // Convert StringBuilder to String
        String htmlString = htmlBuilder.toString();

        return htmlString;
    }


    @EndPointProp(methods = {HTTPMethod.GET}, name="sleep-test", uris="/sleep-test/{time-to-sleep}")
    public NVGenericMap sleep(@ParamProp(name="time-to-sleep") String timeToSleep)
    {
        long tts = Const.TimeInMillis.toMillis(timeToSleep);


        NVGenericMap response = new NVGenericMap();

        long timeReceived = System.currentTimeMillis();
        TaskUtil.sleep(tts);
        long delta = System.currentTimeMillis() - timeReceived;

        response.build(new NVLong("time_received", timeReceived))
                .build(new NVPair("time_slept", Const.TimeInMillis.toString(delta)))
                .build(new NVLong("time_finished", System.currentTimeMillis()));

        return response;
    }


    @EndPointProp(methods = {HTTPMethod.POST}, name="testjson", uris="/testjson/{api-id}")
    public NVGenericMap testJson(@ParamProp(name="nvgm", source = Const.ParamSource.PAYLOAD) NVGenericMap nvgm,
                                 @ParamProp(name="api-id") String apiID)
    {
       assert(nvgm != null);

       nvgm.build("api-id", apiID).build(new NVEnum("time_in_millis", Const.TimeInMillis.DAY));

       return nvgm;
    }


    @EndPointProp(methods = {HTTPMethod.POST}, name="testdata", uris="/testdata")
    public void testDataObject(@ParamProp(name="dataObject", source = Const.ParamSource.PAYLOAD) DataObject dObject)
    {
        assert(dObject != null);
        System.out.println(dObject);
    }

    @EndPointProp(methods = {HTTPMethod.GET}, name="dateTester", uris="/testdate")
    @SecurityProp(permissions = SecurityModel.PERM_RESOURCE_ANY)
    public Date testDataObject()
    {
        return new Date();
    }


    @EndPointProp(methods = {HTTPMethod.GET, HTTPMethod.POST}, name="test", uris="/test/{intv}/{bool}/{tim}")
    public void testnot(@ParamProp(name="intv") int hif, @ParamProp(name="bool") boolean on, @ParamProp(name="tim", optional = true)Const.TimeInMillis tim)
    {
        System.out.println( hif + " " + on + " " + tim);
    }


    @EndPointProp(methods = {HTTPMethod.GET}, name="noparam", uris="/noparam")
    public void noparam()
    {
        System.out.println( "empty");
    }

    @EndPointProp(methods = {HTTPMethod.GET}, name="invalid", uris="/not-set,/invalid")
    public void invalid()
    {
        System.out.println( "empty");
    }

    @EndPointProp(methods = {HTTPMethod.GET}, name="array", uris="/array/{string-array}/{int-array}/{long-array}")
    public void array(@ParamProp(name="string-array") String[] strArray, @ParamProp(name="int-array", optional = true) Integer[] intArray, @ParamProp(name="long-array", optional = true)long[] longArray)
    {
        System.out.println(Arrays.toString(strArray));
        System.out.println(Arrays.toString(intArray));
        System.out.println(Arrays.toString(longArray));
    }


    @EndPointProp(methods = {HTTPMethod.GET}, name="array-invalid", uris="/array-invalid/{string-array}/{int-array}/{long-array}")
    public void arrayInvalid(@ParamProp(name="string-array") String[] strArray, @ParamProp(name="string-array", optional = true) Integer[] intArray, @ParamProp(name="long-array", optional = true)long[] longArray)
    {
        System.out.println(Arrays.toString(strArray));
        System.out.println(Arrays.toString(intArray));
        System.out.println(Arrays.toString(longArray));
    }



    @SecurityProp(authentications = {CryptoConst.AuthenticationType.NONE})
    public void empty(){};
}
