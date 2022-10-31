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

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.subject.Subject;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPStatusCode;


import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;



@SuppressWarnings("serial")
public class ShiroSessionStatusServlet
    extends ShiroBaseServlet
{
	


	@Override
	public void doGet(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException, IOException
    {
		Subject subject = SecurityUtils.getSubject();

		if (subject == null || !subject.isAuthenticated())
		{
			log.info("security check required and user not authenticated");

			if (subject != null && subject.getSession() != null)
			{
				try
                {
					subject.getSession().stop();
				}
				catch(InvalidSessionException e)
                {
					log.info("Error " + e);
				}
			}

			resp.sendError(HTTPStatusCode.UNAUTHORIZED.CODE);
			
			return;
		}

		log.info("Subject check " + subject.getPrincipal() + ":" + subject.getSession().getId());
		resp.setStatus(HTTPStatusCode.OK.CODE);
	}

	/**
	 * @see ShiroBaseServlet#isSecurityCheckRequired(HTTPMethod, HttpServletRequest)
	 */
	@Override
	protected boolean isSecurityCheckRequired(HTTPMethod httpMethod, HttpServletRequest req)
    {
		return false;
	}

}