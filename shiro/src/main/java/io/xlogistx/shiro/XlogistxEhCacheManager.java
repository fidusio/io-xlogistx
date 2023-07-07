/*
 * Copyright (c) 2012-2017 ZoxWeb.com LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package io.xlogistx.shiro;

import io.xlogistx.shiro.cache.ShiroJCacheManager;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.util.Destroyable;
import org.apache.shiro.util.Initializable;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.util.ResourceManager;

import java.io.Closeable;
import java.util.HashSet;
import java.util.Iterator;


/**
 * @author mnael
 *
 */
public class XlogistxEhCacheManager
	extends ShiroJCacheManager
    implements CacheManager, Initializable, Destroyable
{
	public static final String RESOURCE_NAME = "XLOGISTX_EH_CACHE_MANAGER";
	
	public static final LogWrapper log = new LogWrapper(XlogistxEhCacheManager.class).setEnabled(true);
	
	//private static final HashSet<EhCacheManager> CACHE_SET = new HashSet<>();
	
	private static final CacheObject CACHE_OBJECT = new CacheObject();
	
	
	public static class CacheObject
		implements Closeable
	{
		final HashSet<ShiroJCacheManager> cacheSet = new HashSet<>();
		
		CacheObject()
		{
			ResourceManager.SINGLETON.register(RESOURCE_NAME, this);
		}
		
		void add(ShiroJCacheManager eh)
		{
			if(log.isEnabled()) log.getLogger().info("Adding shiro cache " + eh);
			synchronized(cacheSet)
			{
				cacheSet.add(eh);
			}
			
		}

		@Override
		public void close() 
		{
			// TODO Auto-generated method stub
		
			
			synchronized(cacheSet)
	        {
				if(log.isEnabled()) log.getLogger().info("Started destroy all " + cacheSet.size() + " to be destroyed.");
			
				cacheSet.iterator();
				
				Iterator<ShiroJCacheManager> it = cacheSet.iterator();

				while (it.hasNext())
	            {
					try
	                {
						ShiroJCacheManager ecm = it.next();
						ecm.destroy();
						if(log.isEnabled()) log.getLogger().info("Destroyed:" + ecm);
					}
					catch(Exception e)
	                {
						e.printStackTrace();
					}
				}

				cacheSet.clear();
				if(log.isEnabled()) log.getLogger().info("Finished destroy all left size: " + cacheSet.size());
			}
			
		}
		
		
	}
	
	
	public XlogistxEhCacheManager()
    {
		super();
		CACHE_OBJECT.add(this);	
		if(log.isEnabled()) log.getLogger().info("Created set size: " + CACHE_OBJECT.cacheSet.size());
	}
	
	public static void destroyAll()
    {
		CACHE_OBJECT.close();
	}

}