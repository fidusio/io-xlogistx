package io.xlogistx.shiro.cache;

import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.zoxweb.server.util.cache.JCacheListener;
import org.zoxweb.shared.util.SUS;

import javax.cache.Cache.Entry;
import java.util.*;
import java.util.function.Consumer;
import java.util.logging.Logger;

public class ShiroJCache<K, V> implements Cache<K, V> {

	private javax.cache.Cache<K, V> cache;
	private JCacheListener<K,V> cacheListener = new JCacheListener<K,V>();
	private static Logger log = Logger.getLogger(ShiroJCache.class.getName());
 	
	
	
	
	///MutableCacheEntryListenerConfiguration mclc;
	
	public ShiroJCache(javax.cache.Cache<K,V>  cache)
	{
		SUS.checkIfNulls("Null cache", cache);
		this.cache = cache;
		cache.registerCacheEntryListener(JCacheListener.toConfiguration(cacheListener));
	}
	
	
	@Override
	public V get(K key) throws CacheException {
		// TODO Auto-generated method stub
		 if (key == null)
             return null;
		 
		 V v = cache.get(key);
		 //log.info("key:" + key + " value:" + v);
		return v;
	}

	@Override
	public V put(K key, V value) throws CacheException {
		SUS.checkIfNulls("Null key or value", key, value);
		// TODO Auto-generated method stub
		 //log.info(key.getClass()+":key:" + key + " " +value.getClass() + ":value:" + value);
		return cache.getAndPut(key, value);
	}

	@Override
	public  V remove(K key) throws CacheException {
		// TODO Auto-generated method stub
		SUS.checkIfNulls("Null key", key);
		return cache.getAndRemove(key);
	}
		

	@Override
	public void clear() throws CacheException {
		// TODO Auto-generated method stub
		cache.clear();
		log.info("Cleared");
	}

	@Override
	public  int size() {
		return cacheListener.size();
		// TODO Auto-generated method stub
//		Iterator<Entry<K, V>> it = cache.iterator();
//		int ret = 0;
//		while(it.hasNext())
//		{
//			it.next();
//			ret++;
//		}
//		
//	
//		return ret;
	}

	@Override
	public synchronized Set<K> keys() {
		// TODO Auto-generated method stub
		 Iterator<Entry<K, V>> it = cache.iterator();
		 Set<K> ret = new HashSet<K>();
		 Consumer<Entry<K, V>> c = new Consumer<Entry<K, V>>() {

			private Set<K> set;
			
			
			Consumer<Entry<K, V>> init(Set<K> set)
			{
				this.set = set;
				return this;
			}
			@Override
			public void accept(Entry<K, V> t) 
			{
				set.add(t.getKey());
			}
			 
		 }.init(ret);
		
		 it.forEachRemaining(c);
		return ret;
	}

	@Override
	public synchronized Collection<V> values() {
		 Iterator<Entry<K, V>> it = cache.iterator();
		 List<V> ret = new ArrayList<V>();
		 Consumer<Entry<K, V>> c = new Consumer<Entry<K, V>>() {

			private List<V> list;
			
			
			Consumer<Entry<K, V>> init(List<V> list)
			{
				this.list = list;
				return this;
			}
			@Override
			public void accept(Entry<K, V> t) 
			{
				if(t!= null)
				list.add(
						t.getValue());
			}
			 
		 }.init(ret);

		 it.forEachRemaining(c);
		return ret;
	}
	
	public boolean equals(Object o)
	{
		if (o == this)
		{
			return true;
		}
		
		javax.cache.Cache<?,?> temp = null;
		if (o instanceof javax.cache.Cache)
		{
			temp = (javax.cache.Cache<?, ?>) o;
		}	
		else if (o instanceof ShiroJCache)
		{
			temp = ((ShiroJCache<?,?>)o).cache;
		}
		
		if (temp != null)
		{
			cache.equals(temp);
		}
		
		return false;
	}
	
	public int hashCode()
	{
		return cache.hashCode();
	}
}

