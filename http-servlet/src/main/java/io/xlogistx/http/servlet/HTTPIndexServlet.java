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

import org.zoxweb.server.util.ApplicationConfigManager;
import org.zoxweb.shared.data.ApplicationConfigDAO;
import org.zoxweb.shared.data.ApplicationConfigDAO.ApplicationDefaultParam;
import org.zoxweb.shared.util.SharedStringUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Logger;

@SuppressWarnings("serial")
public class HTTPIndexServlet
    extends HttpServlet
{
	
	private static final transient Logger log = Logger.getLogger("");
	
	public void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException,
				   IOException
	{
		ApplicationConfigDAO acd = null;
		String url = null;
		try
		{
			acd = ApplicationConfigManager.SINGLETON.loadDefault();
			//req.getLocalAddr();
			String forwardTo = SharedStringUtil.embedText(SharedStringUtil.trimOrNull(acd.lookupValue(ApplicationDefaultParam.FORWARD_URL)), "$$LOCAL_IP$$",  SharedStringUtil.toLowerCase(req.getLocalAddr()));
			url = resp.encodeRedirectURL(forwardTo);
			
		}
		catch( Exception e)
		{
			log.info("error:" + e);
		}
		
		
		if ( url != null)
		{
			log.info("redirect:" + req.getRequestURL() + (req.getRequestURI() != null ? req.getRequestURI() :"")+ " from:"+ req.getHeader("User-Agent") + "-" + req.getRemoteAddr() + " Redirected URL:" + url);
			resp.sendRedirect( url);
		}
		
	}
}
