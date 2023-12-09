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
package io.xlogistx.shiro.service;

import org.apache.shiro.authc.AuthenticationToken;
import org.zoxweb.server.http.HTTPAPIEndPoint;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.security.AccessException;
import org.zoxweb.shared.security.shiro.ShiroSubjectData;

import java.io.IOException;

public class ShiroProxyAuthentication
{
	public static final String AUTHENTICATION_URI = "shiro/loginProxy";
	
	
	public static final LogWrapper log = new LogWrapper(ShiroProxyAuthentication.class);
	
	public static ShiroSubjectData login(AuthenticationToken token, HTTPAPIEndPoint<AuthenticationToken, ShiroSubjectData> endpoint)
		throws AccessException, IOException
    {

		return endpoint.syncCall(token).getData();
	}

}