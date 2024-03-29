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
package io.xlogistx.http.servlet.shiro;

import org.apache.shiro.web.env.EnvironmentLoaderListener;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.zoxweb.server.logging.LogWrapper;

import javax.servlet.ServletContextEvent;



public abstract class ShiroBaseWebListener
    extends EnvironmentLoaderListener
{

	public final static LogWrapper log = new LogWrapper(ShiroBaseWebListener.class.getName());
	
	protected abstract void init(WebSecurityManager wsm);

	@Override
	public void contextInitialized(ServletContextEvent sce)
    {
		if(log.isEnabled()) log.getLogger().info("SHIRO ENV Initializing ----------------------------------------------------");
		init(initEnvironment(sce.getServletContext()).getWebSecurityManager());
		if(log.isEnabled()) log.getLogger().info("SHIRO ENV Initialized ----------------------------------------------------");
	}	
	
	@Override
	public void contextDestroyed(ServletContextEvent sce)
    {
		super.contextDestroyed(sce);
	}

}