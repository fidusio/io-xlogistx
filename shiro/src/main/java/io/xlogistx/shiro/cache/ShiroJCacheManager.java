package io.xlogistx.shiro.cache;


import org.apache.shiro.ShiroException;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.util.Destroyable;
import org.apache.shiro.util.Initializable;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.util.cache.JCacheExpiryPolicy;

import javax.cache.Caching;
import javax.cache.configuration.MutableConfiguration;
import javax.cache.expiry.Duration;
import java.util.Iterator;
import java.util.logging.Logger;


public class ShiroJCacheManager 
	implements CacheManager, Initializable, Destroyable
{
	 javax.cache.CacheManager cacheManager = null;
	 MutableConfiguration<?, ?> configuration = null;
	 
	 private static final Logger log = Logger.getLogger(ShiroJCacheManager.class.getName());

	

	@Override
	public void destroy()
			throws Exception
		
	{
		// TODO Auto-generated method stub
		 Iterable<String> names = cacheManager.getCacheNames();
		 Iterator<String> it = names.iterator();
		 while(it.hasNext())
		 {
			 IOUtil.close(cacheManager.getCache(it.next()));
		 }
		
		
	}

	@Override
	public synchronized void init()
			throws ShiroException
	{
		// TODO Auto-generated method stub
		log.info("Started");
		if (cacheManager == null)
		{
			log.info("cacheManager null");
			cacheManager =  Caching.getCachingProvider().getCacheManager();
			configuration = new MutableConfiguration<Object, Object>().setTypes(Object.class, Object.class)
					.setExpiryPolicyFactory(JCacheExpiryPolicy.factoryOf(Duration.ETERNAL, Duration.ETERNAL, Duration.ETERNAL))
					.setStoreByValue(false);
		}
		log.info("ended");
		
	}

	@SuppressWarnings("unchecked")
	@Override
	public <K, V> Cache<K, V> getCache(String cacheName)
			throws CacheException
	{
		
		//log.info("cacheName:" + cacheName);
		javax.cache.Cache<K, V> ret = cacheManager.getCache(cacheName);
		
		if(ret == null)
		{
			ret = (javax.cache.Cache<K, V>) cacheManager.createCache(cacheName, configuration);
			log.info("cacheName:" + cacheName + " created " + ret);
		}
		
		// TODO Auto-generated method stub
		return new ShiroJCache<K,V>(ret);
	}
	
	
	public javax.cache.CacheManager getCacheManager() 
	{
		return cacheManager;
	}

	public void setCacheManager(javax.cache.CacheManager cacheManager)
	{
		this.cacheManager = cacheManager;
	}

}
