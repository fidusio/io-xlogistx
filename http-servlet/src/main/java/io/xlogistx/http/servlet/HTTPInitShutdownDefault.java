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
package io.xlogistx.http.servlet;


import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.ApplicationConfigManager;
import org.zoxweb.server.util.ServiceManager;
import org.zoxweb.shared.data.ApplicationConfigDAO;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;



public class HTTPInitShutdownDefault
	implements ServletContextListener
{

	public final static LogWrapper log = new LogWrapper(HTTPInitShutdownDefault.class);
	//private NIOConfig nioConfig = null;
	//private IPBlockerListener ipBlocker = null;
	public void contextInitialized(ServletContextEvent event) 
	{
		TaskUtil.setThreadMultiplier(8);
		try
		{
			//log.info("" + ApplicationConfigManager.SINGLETON.loadDefault().getProperties());
			ServiceManager.SINGLETON.loadServices();
//			String filename = ApplicationConfigManager.SINGLETON.loadDefault().lookupValue(ApplicationDefaultParam.NIO_CONFIG);
//			if (filename != null)
//			{
//				try
//				{
//					File file = ApplicationConfigManager.SINGLETON.locateFile(ApplicationConfigManager.SINGLETON.loadDefault(), filename);
//					ConfigDAO configDAO = GSONUtil.fromJSON(IOUtil.inputStreamToString(new FileInputStream(file), true));
//					log.info("" + configDAO);
//					NIOConfig nioConfig = new NIOConfig(configDAO);
//					nioConfig.createApp();
//					ResourceManager.SINGLETON.map(NIOConfig.RESOURCE_NAME, nioConfig);
//				}
//				catch(Exception e)
//				{
//					e.printStackTrace();
//				}
//			}
//			
//			
//			
//			filename = ApplicationConfigManager.SINGLETON.loadDefault().lookupValue("ip_blocker_config");
//			if (filename != null)
//			{
//				try
//				{
//					File file = ApplicationConfigManager.SINGLETON.locateFile(ApplicationConfigManager.SINGLETON.loadDefault(), filename);
//					IPBlockerConfig appConfig = GSONUtil.fromJSON(IOUtil.inputStreamToString(new FileInputStream(file), true), IPBlockerConfig.class);
//					IPBlockerListener.Creator c = new IPBlockerListener.Creator();
//					//log.info("\n" + GSONUtil.toJSON(appConfig, true, false, false));
//					c.setAppConfig(appConfig);
//					IPBlockerListener ipBlocker = c.createApp();
//					ResourceManager.SINGLETON.map(IPBlockerListener.RESOURCE_NAME, ipBlocker);
//				}
//				catch(Exception e)
//				{
//					e.printStackTrace();
//				}
//			}
		}
		catch( Throwable t)
		{
			log.getLogger().info("error loading default config " + t);
			
			
			try
			{
				ApplicationConfigManager.SINGLETON.save(new ApplicationConfigDAO());
			}
			catch(Exception e)
			{
				log.info("error saving default config " + e);
				//e.printStackTrace();
			}
		}
    	log.getLogger().info("INIT DONE java version:"
            + System.getProperty("java.version")
            + ", "
            + System.getProperty(" java.vm.specification.vendor"));
	}
	
	
	
	public void contextDestroyed(ServletContextEvent event) 
	{
		log.info("destroy started");
		// TODO Auto-generated method stub
		
		
		ServiceManager.SINGLETON.close();
		
//		IOUtil.close(nioConfig);
//		IOUtil.close(ipBlocker);
		TaskUtil.getDefaultTaskScheduler().close();
		TaskUtil.getDefaultTaskProcessor().close();
		log.getLogger().info("destroy done");
	}
}