package io.xlogistx.http.services;

import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.data.AddressDAO;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.security.SecurityConsts;
import org.zoxweb.shared.util.Const;

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

    @EndPointProp(methods = {HTTPMethod.GET, HTTPMethod.POST}, name="test", uris="/test/{intv}/{bool}/{tim}")
    @SecurityProp(authentications = {SecurityConsts.AuthenticationType.ALL})
    public void test(@ParamProp(name="intv") int hif, @ParamProp(name="bool") boolean on, @ParamProp(name="tim")Const.TimeInMillis tim)
    {
        //System.out.println( hif + " " + on + " " + tim);
    }


    @EndPointProp(methods = {HTTPMethod.POST}, name="tester", uris="/testjson")
    @SecurityProp(authentications = {SecurityConsts.AuthenticationType.ALL})
    public void testJson(@ParamProp(name="address", paramSource = Const.ParamSource.PAYLOAD) AddressDAO address)
    {
       assert(address != null);
       System.out.println(address);
    }


    @EndPointProp(methods = {HTTPMethod.POST}, name="tester", uris="/testdata")
    @SecurityProp(authentications = {SecurityConsts.AuthenticationType.ALL})
    public void testDataObject(@ParamProp(name="dataObject", paramSource = Const.ParamSource.PAYLOAD) DataObject dObject)
    {
        assert(dObject != null);
        System.out.println(dObject);
    }
}
