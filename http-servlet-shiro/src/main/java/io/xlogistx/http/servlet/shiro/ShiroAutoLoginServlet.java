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

import io.xlogistx.http.servlet.HTTPServletUtil;
import org.apache.shiro.subject.Subject;
import org.zoxweb.server.http.HTTPRequestAttributes;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.server.util.ServerUtil;
import org.zoxweb.shared.api.APIError;
import org.zoxweb.shared.api.APISecurityManager;
import org.zoxweb.shared.data.AppIDDAO;
import org.zoxweb.shared.http.HTTPAuthenticationBasic;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.util.ResourceManager;
import org.zoxweb.shared.util.ResourceManager.Resource;
import org.zoxweb.shared.util.SharedStringUtil;
import org.zoxweb.shared.util.SharedUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;



@SuppressWarnings("serial")
public class ShiroAutoLoginServlet 
	extends ShiroBaseServlet
{	

	
	public  void doPost(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException
	{
		
		// filter way
		HTTPRequestAttributes hra = (HTTPRequestAttributes) req.getAttribute(HTTPRequestAttributes.HRA);
		
		// no filter
		if(hra == null)
			hra = HTTPServletUtil.extractRequestAttributes(req);
		log.info("Request started");
		
		APISecurityManager<Subject> apiSecurityManager = ResourceManager.SINGLETON.lookup(Resource.API_SECURITY_MANAGER);
		if (apiSecurityManager != null && apiSecurityManager.getDaemonSubject() == null)
		{
			try
			{
				ServerUtil.LOCK.lock();
				if (apiSecurityManager.getDaemonSubject() == null)
				{
					HTTPAuthenticationBasic hab = (HTTPAuthenticationBasic) hra.getHTTPAuthentication();
//					log.info("Authentication:" + hab);
//					log.info("hra:" + hra.getContentType());
//					log.info("Content:" + hra.getContent());
					AppIDDAO appIDDAO = null;
					
					if (!SharedStringUtil.isEmpty(hra.getContent()))
					{
						appIDDAO = GSONUtil.fromJSON(hra.getContent(), AppIDDAO.class);
					}
					else 
					{
						String domainID = SharedUtil.getValue(hra.getParameters().get(AppIDDAO.Param.DOMAIN_ID.getNVConfig()));
						String appID = SharedUtil.getValue(hra.getParameters().get(AppIDDAO.Param.APP_ID.getNVConfig()));
						if (domainID != null && appID != null)
						{
							appIDDAO = new AppIDDAO();
							appIDDAO.setDomainAppID(domainID, appID);
						}
				
					}
					log.info(""+appIDDAO);
					Subject daemon = apiSecurityManager.login(hab.getUser(), null, appIDDAO.getDomainID(), appIDDAO.getAppID(), true);
					
					apiSecurityManager.setDaemonSubject(daemon);
					apiSecurityManager.getDaemonSubject().getSession().touch();
					apiSecurityManager.getDaemonSubject().getSession().setTimeout(-1);
				}
				else
				{
					log.info("Daemon already SET --------:" + Thread.currentThread().getName());
				}
			}
			catch(Exception e)
			{
				e.printStackTrace();
				HTTPServletUtil.sendJSON(null, resp, HTTPStatusCode.UNAUTHORIZED, new APIError("Authentication Error"));
			}
			finally
			{
				ServerUtil.LOCK.unlock();
			}
		}
		else
		{
//			HTTPAuthenticationBasic hab = (HTTPAuthenticationBasic) hra.getHTTPAuthentication();
//			log.info("NOT DAEMON ALREADY SET:" + hra);
//			try
//			{
//				SubjectLoginData ret = FidusStoreSecurityUtil.SINGLETON.autoLogin(FidusStoreAPIManager.SINGLETON.lookupAPIDataStore(FidusStoreAPIManager.FIDUS_STORE_NAME), hab.getUser());
//				
//				SessionDataCacheManager.SINGLETON.associateSessionToSubject(SecurityUtils.getSubject());
//				SecurityUtils.getSubject().getSession().touch();
//				SecurityUtils.getSubject().getSession().setTimeout(Const.TimeInMillis.MINUTE.MILLIS);;
//				ret.loginToken.setSessionID((String) SecurityUtils.getSubject().getSession().getId());
//				HTTPServletUtil.sendJSON(null, resp, HTTPStatusCode.OK, ret.loginToken);
//				
//			}
//			catch(Exception e)
			{
				HTTPServletUtil.sendJSON(null, resp, HTTPStatusCode.UNAUTHORIZED, new APIError("Authentication Error"));
			}
			log.info("Daemon already SET ++++++:" + Thread.currentThread().getName());
		}
		
		log.info("Ended:" + Thread.currentThread().getName());
		
	}
	
	@Override
	protected boolean isSecurityCheckRequired(HTTPMethod httpMethod, HttpServletRequest req)
	{
		return false;
	}
	
}