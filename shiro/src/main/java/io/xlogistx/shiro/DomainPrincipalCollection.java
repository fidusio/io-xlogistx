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

import org.apache.shiro.subject.SimplePrincipalCollection;
import org.zoxweb.shared.util.AppID;
import org.zoxweb.shared.util.SharedStringUtil;
import org.zoxweb.shared.util.SharedUtil;
import org.zoxweb.shared.util.SubjectID;

@SuppressWarnings("serial")
public class DomainPrincipalCollection
    extends SimplePrincipalCollection
    implements AppID<String>, SubjectID<String>
{

	protected String domain_id;
	protected String application_id;
	protected String subject_gid;
	protected String token_subject_id;

	/**
     *
	 * @param principal the login id ie email
	 * @param subjectGID subject global id as uuid
	 * @param realmName
	 * @param domainID
	 * @param applicationID
	 */
	public DomainPrincipalCollection(Object principal, String subjectGID, String realmName, String domainID, String applicationID, String jwtSubjectID)
    {
		super(principal, realmName);
		SharedUtil.checkIfNulls("Subject GID can't be null", subjectGID);
		domain_id = SharedStringUtil.toLowerCase(domainID);
		application_id = SharedStringUtil.toLowerCase(applicationID);
		subject_gid = subjectGID;
		token_subject_id = jwtSubjectID;
		
		// first on to add for optimization issue
		if(token_subject_id != null)
		{
			add(token_subject_id, realmName);
		}
//		if (domain_id != null)
//		{
//			add(domain_id, realmName);
//		}
//		if (application_id != null)
//		{
//			add(application_id, realmName);
//		}
//		if(user_id != null)
//		{
//			add(user_id, realmName);
//		}
		
		
		
    }
	
    public String getDomainID()
    {
		return domain_id;
	}
	
//	public String getApplicationID()
//    {
//		return application_id;
//	}

	/**
	 * This is a second unique identifier
	 *
	 * @return user id
	 */
	public String getUserID()
    {
		return subject_gid;
	}

	@Override
	public void setDomainID(String domainID) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public String getSubjectID() {
		// TODO Auto-generated method stub
		return (String) getPrimaryPrincipal();
	}

	@Override
	public void setSubjectID(String id) {
		// TODO Auto-generated method stub
		
	}

	public String getSubjectGID()
	{
		return subject_gid;
	}

	@Override
	public String getAppID() {
		// TODO Auto-generated method stub
		return application_id;
	}

	@Override
	public void setAppID(String appID) {
		// TODO Auto-generated method stub
		
	}
	
	public String getJWSubjectID()
	{
		return token_subject_id;
	}
	

}