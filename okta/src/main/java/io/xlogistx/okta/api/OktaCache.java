package io.xlogistx.okta.api;


import org.zoxweb.shared.util.*;

public class OktaCache {

    public static final OktaCache SINGLETON = new OktaCache();
    public enum CacheType
    {
        GROUP,
        APP,
        RATE_CONTROLLER,
        RATE_COUNTER,
    }


    public enum RateCount
    {
        SUCCESS,
        FAILED
    }

    private final TypedCache typedCache = new TypedCache();

    private OktaCache()
    {

        for(CacheType ctn : CacheType.values())
            typedCache.registerType(ctn);


        for(RateCount rc : RateCount.values())
            getCache().addObject(CacheType.RATE_COUNTER, new RateCounter(SUS.enumName(rc)));




    }

    public OktaCache addGroup(OktaGroup group)
    {
        SUS.checkIfNulls("Group or id null", group);

        typedCache.addObject(CacheType.GROUP, group.getProfile().getName(), group);
        return this;
    }
    public OktaCache deleteGroup(String group)
    {
        if(group != null)
            typedCache.removeObject(CacheType.GROUP, group);
        return this;
    }
    public OktaGroup lookupGroup(String group)
    {
        SUS.checkIfNulls("Group or id null", group);
        return typedCache.lookupObject(CacheType.GROUP, group);
    }

    public OktaGroup[] groups()
    {
        return typedCache.getValues(CacheType.GROUP).toArray(new OktaGroup[0]);

    }

    public RateCounter rateCounter(RateCount rc)
    {
        return typedCache.lookupObject(CacheType.RATE_COUNTER, rc);
    }

    public RateController rateController(String name)
    {
        return typedCache.lookupObject(CacheType.RATE_CONTROLLER, name);
    }

    public <T> T lookupObject(Enum<?> cacheType, String cachedObjectName)
    {
        return typedCache.lookupObject(cacheType, cachedObjectName);
    }


    public <T> T lookupObject(String cacheType, String cachedObjectName)
    {
        return typedCache.lookupObject(cacheType, cachedObjectName);
    }







    public TypedCache getCache()
    {
        return typedCache;
    }





}
