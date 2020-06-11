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
package io.xlogistx.shiro.authc;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.shared.crypto.PasswordDAO;
import org.zoxweb.shared.util.SharedStringUtil;

public class PasswordCredentialsMatcher
	implements CredentialsMatcher
{

	/**
	 * @see CredentialsMatcher#doCredentialsMatch(AuthenticationToken, AuthenticationInfo)
	 */
	@Override
	public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info)
    {
		if (!token.getPrincipal().equals(info.getPrincipals().getPrimaryPrincipal()))
		{
			return false;
		}
		
		try
        {
			if (token instanceof DomainUsernamePasswordToken
                    && ((DomainUsernamePasswordToken)token).isAutoAuthenticationEnabled())
			{
				return true;
			}
			
			if (info.getCredentials() instanceof PasswordDAO)
			{
				PasswordDAO passwordDAO = (PasswordDAO) info.getCredentials();
				String password = null;
				
				if (token.getCredentials() instanceof char[])
				{
					password = new String((char[])token.getCredentials());
				}
				else if (token.getCredentials() instanceof byte[])
				{
					password = SharedStringUtil.toString((byte[])token.getCredentials());
				}
				else if(token.getCredentials() instanceof String)
				{
					password = (String) token.getCredentials();
				}
	
				return CryptoUtil.isPasswordValid(passwordDAO, password);
			}
		}
		catch (Exception e)
        {
			e.printStackTrace();
		}
		
		return false;
	}

}