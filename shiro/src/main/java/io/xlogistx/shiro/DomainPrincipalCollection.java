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
import org.zoxweb.shared.security.PrincipalIDBase;
import org.zoxweb.shared.util.AppID;
import org.zoxweb.shared.util.SUS;
import org.zoxweb.shared.util.SubjectGUIDBase;

@SuppressWarnings("serial")
public class DomainPrincipalCollection
    extends SimplePrincipalCollection
    implements AppID<String>, SubjectGUIDBase<String>, PrincipalIDBase<String>
{

	protected String domain_id;
	protected String application_id;
	protected String subject_guid;
	protected String token_subject_id;
	/** GUID of the app record the subject logged into (dual ownership, 2026-10-20), null for a login without app. */
	protected String app_guid;

	/**
     *
	 * @param principal the login id ie email
	 * @param subjectGUID subject global id as uuid
	 * @param realmName
	 * @param domainID
	 * @param applicationID
	 */
	public DomainPrincipalCollection(Object principal, String subjectGUID, String realmName, String domainID, String applicationID, String jwtSubjectID)
    {
		this(principal, subjectGUID, realmName, domainID, applicationID, jwtSubjectID, null);
	}

	/**
	 * @param appGUID the GUID of the stored app record of {@code domainID}/{@code applicationID}, resolved
	 *                by the realm at login; null for a login without app or an app that has no record
	 */
	public DomainPrincipalCollection(Object principal, String subjectGUID, String realmName, String domainID, String applicationID, String jwtSubjectID, String appGUID)
    {
		super(principal, realmName);
		SUS.checkIfNulls("Subject GID can't be null", subjectGUID);
		domain_id = SUS.toLowerCase(domainID);
		application_id = SUS.toLowerCase(applicationID);
		this.subject_guid = subjectGUID;
		token_subject_id = jwtSubjectID;
		app_guid = SUS.trimOrNull(appGUID);
		
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
//	public String getUserID()
//    {
//		return subject_guid;
//	}

	@Override
	public void setDomainID(String domainID) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public String getPrincipalID() {
		// TODO Auto-generated method stub
		return (String) getPrimaryPrincipal();
	}


	public String getSubjectGUID()
	{
		return subject_guid;
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

	/**
	 * @return the GUID of the app record the subject logged into — the {@code app_guid} stamped on
	 * the rows it creates in the app's registered classes — or null for a login without app
	 */
	public String getAppGUID()
	{
		return app_guid;
	}
	

}