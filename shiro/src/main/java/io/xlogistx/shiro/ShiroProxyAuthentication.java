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

import org.zoxweb.server.http.HTTPCall;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.SSLCheckDisabler;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.api.APIException;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.security.AccessException;
import org.zoxweb.shared.security.shiro.LoginStatusDAO;
import org.zoxweb.shared.security.shiro.ShiroLoginTokenDAO;

import java.io.IOException;

public class ShiroProxyAuthentication
{
	public static final String AUTHENTICATION_URI = "shiro/loginProxy";
	
	
	public static final LogWrapper log = new LogWrapper(ShiroProxyAuthentication.class);
	
	public static LoginStatusDAO login(String httpUrl, boolean sslCheckOff, String domainID, String appID, String realm, String username, String password)
		throws AccessException, IOException
    {

		HTTPMessageConfig hcc = new HTTPMessageConfig();
		hcc.setURL(httpUrl);
		hcc.setURI(AUTHENTICATION_URI);
		hcc.setMethod(HTTPMethod.POST);
		hcc.setContent(GSONUtil.toJSON(new ShiroLoginTokenDAO(domainID, appID, realm, username, password), false));
		HTTPCall call = new HTTPCall( hcc, sslCheckOff ? SSLCheckDisabler.SINGLETON : null);
		HTTPResponseData rd = null;
		
		HTTPCallException httpCallException = null;
		HTTPStatusCode status = null;

		try
        {
			rd = call.sendRequest();
			status = HTTPStatusCode.statusByCode(rd.getStatus());

			if (status == HTTPStatusCode.OK)
			{
				try
                {
					
					String json = new String(rd.getData());
					if(log.isEnabled()) log.getLogger().info("\n" +json);
					return GSONUtil.fromJSON( json, LoginStatusDAO.class);
				}
				catch (AccessException | APIException e)
                {
					e.printStackTrace();
				}
			}
		}
		catch (HTTPCallException e)
        {
			httpCallException = e;
			status = HTTPStatusCode.statusByCode( e.getResponseData().getStatus());
		}
		catch(IOException e)
        {
			throw e;
		}

		if (status == HTTPStatusCode.UNAUTHORIZED)
		{
			throw new AccessException("Invalid credentials" );
		}

		throw httpCallException;
	}

}