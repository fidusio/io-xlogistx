package io.xlogistx.http.services;

import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.data.AddressDAO;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.security.SecurityConsts;
import org.zoxweb.shared.util.Const;

import java.util.Date;

@SecurityProp(authentications = {SecurityConsts.AuthenticationType.BASIC})
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





    @EndPointProp(methods = {HTTPMethod.POST}, name="testjson", uris="/testjson")
    public void testJson(@ParamProp(name="address", source = Const.ParamSource.PAYLOAD) AddressDAO address)
    {
       assert(address != null);
       System.out.println(address);
    }


    @EndPointProp(methods = {HTTPMethod.POST}, name="testdata", uris="/testdata")
    public void testDataObject(@ParamProp(name="dataObject", source = Const.ParamSource.PAYLOAD) DataObject dObject)
    {
        assert(dObject != null);
        System.out.println(dObject);
    }

    @EndPointProp(methods = {HTTPMethod.GET}, name="dateTester", uris="/testdate")
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

    @SecurityProp(authentications = {SecurityConsts.AuthenticationType.NONE})
    public void empty(){};
}
