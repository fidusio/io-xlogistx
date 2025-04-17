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
import org.zoxweb.server.util.ApplicationConfigManager;
import org.zoxweb.shared.data.ApplicationConfigDAO.ApplicationDefaultParam;
import org.zoxweb.shared.http.HTTPMediaType;
import org.zoxweb.shared.util.Const;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;


@SuppressWarnings("serial")
public class HTTPAppVersionServlet 
	extends HttpServlet
{
	public final static LogWrapper log = new LogWrapper(HTTPAppVersionServlet.class);
	private AtomicReference<String> version = new AtomicReference<String>();
	
	
	public void doGet(HttpServletRequest req, HttpServletResponse resp)
			  throws ServletException, IOException 
	{
		if (version.get() == null)
		{
			log.getLogger().info("version is null");
			String jsonResource = ApplicationConfigManager.SINGLETON.loadDefault().lookupValue(ApplicationDefaultParam.APPLICATION_VERSION_RESOURCE);
			log.getLogger().info(jsonResource);
			String json = HTTPServletUtil.inputStreamToString(getServletContext(), jsonResource);
			version.set(json);
		}
		
		log.getLogger().info(version.get());
		
		resp.setContentType(HTTPMediaType.APPLICATION_JSON.getValue());
		resp.setCharacterEncoding(Const.UTF_8);
		resp.addHeader("Access-Control-Allow-Origin", "*");
		resp.getWriter().write(version.get());
		
	}

	
	
	
}
