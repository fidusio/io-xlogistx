package io.xlogistx.common.http;

import org.zoxweb.shared.util.SharedStringUtil;




import java.util.LinkedHashMap;
import java.util.Map;


public class URIMap<V> {
    private final Map<String, V> uriMap = new LinkedHashMap<>();

    public URIMap()
    {

    }

    public V put(String uri, V v)
    {
        synchronized (uriMap)
        {
            return uriMap.put(normalize(uri), v);
        }
    }

    public V remove(String uri)
    {
        synchronized(uriMap)
        {
            return uriMap.remove(normalize(uri));
        }
    }


    public V get(String literalURI)
    {
        return uriMap.get(literalURI);
    }

    /**
     * This method perform smart lookup on the uri for instance
     * <br> if the uri=/user/info/user-id and the endpoint stored uri is /user/info it is considered a match
     * @param uri looking for
     * @return mapped value
     */
    public V lookup(String uri)
    {
        V ret  = null;
        uri = normalize(uri);
        // try to match
        ret = uriMap.get(uri);

        if (ret == null)
        {
            String[] tokens = SharedStringUtil.parseString(uri, "/", true);

            for(int i = tokens.length - 1 ; i > 0; i--)
            {
                ret =  uriMap.get(SharedStringUtil.concat("/", i, tokens));
                if(ret != null)
                    break;
            }


        }
        return ret;
    }

    /**
     * @return all the supported URIs
     */
    public String[] allURIs()
    {
        return uriMap.keySet().toArray(new String[0]);
    }

    /**
     * @return the size of the mapped URIs
     */
    public int size()
    {
        return uriMap.size();
    }

    public static String normalize(String str)
    {
        str = SharedStringUtil.toTrimmedLowerCase(str);
        if(str.endsWith("/") && str.length() > 1)
        {
            str = str.substring(0, str.length() - 1);
        }

        int indexQuestionMark =  str.indexOf("?");

        if(indexQuestionMark != -1)
        {
            str = str.substring(0, indexQuestionMark);
        }

        return str;
    }


}
