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

import org.apache.shiro.authc.UsernamePasswordToken;
import org.zoxweb.shared.util.AppID;
import org.zoxweb.shared.util.SharedStringUtil;
import org.zoxweb.shared.util.SubjectID;

@SuppressWarnings("serial")
public class DomainUsernamePasswordToken
    extends UsernamePasswordToken
    implements AppID<String>, SubjectID<String>
{

	private String domain_id;
	private String app_id;
	private String subject_guid;
	private boolean autoAuthenticationEnabled = false;

	public DomainUsernamePasswordToken()
    {
		
	}
	
	public DomainUsernamePasswordToken(final String username, final String password,
                                       final boolean rememberMe, final String host, final String domainID)
    {
		this(username, password, rememberMe, host, domainID, null);
	}
	
	public DomainUsernamePasswordToken(final String username, final String password,
                                       final boolean rememberMe, final String host, final String domainID, String applicationID)
    {
		super(SharedStringUtil.toLowerCase(username), password, rememberMe, host);
		setDomainID(domainID);
		setAppID(applicationID);
		//setUserID(realmID);
	}

	public String getDomainID()
    {
		return domain_id;
	}

	public void setDomainID(String domainID)
    {
		this.domain_id = SharedStringUtil.trimOrEmpty(SharedStringUtil.toLowerCase(domainID));
	}
	
	public String getAppID()
    {
		return app_id;
	}

	public void setAppID(String applicationID)
    {
		this.app_id = SharedStringUtil.trimOrEmpty(SharedStringUtil.toLowerCase(applicationID));
	}

	public String getSubjectGUID()
    {
		return subject_guid;
	}
	
	public void setSubjectGUID(String subject_guid)
    {
		this.subject_guid = subject_guid;
	}
	
	
	
	public boolean isAutoAuthenticationEnabled()
    {
		return autoAuthenticationEnabled;
	}

	public void setAutoAuthenticationEnabled(boolean autoAuthenticationEnabled)
    {
		this.autoAuthenticationEnabled = autoAuthenticationEnabled;
	}

	@Override
	public String getSubjectID() {
		// TODO Auto-generated method stub
		return getUsername();
	}

	@Override
	public void setSubjectID(String subjectID) {
		// TODO Auto-generated method stub
		setUsername(subjectID);
	}

	

}