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

import io.xlogistx.shiro.DomainPrincipalCollection;
import org.apache.shiro.authc.SimpleAuthenticationInfo;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;


@SuppressWarnings("serial")
public class DomainAuthenticationInfo
    extends SimpleAuthenticationInfo
{

	public DomainAuthenticationInfo(Object principal, String subjectGUID, Object credentials, String realmName, String domainID, String applicationID, String jwtSubjectID)
    {
		Set<Object> principalCollection = new LinkedHashSet<>();
		principalCollection.add(principal);
		if (subjectGUID != null)
			principalCollection.add(UUID.fromString(subjectGUID));

		this.principals = new DomainPrincipalCollection(principalCollection, subjectGUID, realmName, domainID, applicationID, jwtSubjectID);
		 
		this.credentials = credentials;
	}

	
//	 public DomainAuthenticationInfo(Object principal, Object credentials, String realmName, String domainID) 
//	 {
//		this(principal, credentials, realmName, domainID, null);
//	 }
	
}
