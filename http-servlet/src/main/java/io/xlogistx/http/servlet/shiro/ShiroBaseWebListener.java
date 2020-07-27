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

import javax.servlet.ServletContextEvent;
import java.util.logging.Logger;


public abstract class ShiroBaseWebListener
    extends EnvironmentLoaderListener
{

	private static final transient Logger log = Logger.getLogger(ShiroBaseWebListener.class.getName());
	
	protected abstract void init(WebSecurityManager wsm);

	@Override
	public void contextInitialized(ServletContextEvent sce)
    {
		log.info("SHIRO ENV Initializing ----------------------------------------------------");
		init(initEnvironment(sce.getServletContext()).getWebSecurityManager());
		log.info("SHIRO ENV Initialized ----------------------------------------------------");
	}	
	
	@Override
	public void contextDestroyed(ServletContextEvent sce)
    {
		super.contextDestroyed(sce);
	}

}