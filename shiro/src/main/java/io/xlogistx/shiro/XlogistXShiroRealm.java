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

import io.xlogistx.shiro.authc.DomainAuthenticationInfo;
import io.xlogistx.shiro.authc.DomainUsernamePasswordToken;
import io.xlogistx.shiro.authc.JWTAuthenticationToken;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.api.APIAppManager;
import org.zoxweb.shared.api.APISecurityManager;
import org.zoxweb.shared.crypto.PasswordDAO;
import org.zoxweb.shared.data.AppDeviceDAO;
import org.zoxweb.shared.data.UserIDDAO;
import org.zoxweb.shared.security.SubjectAPIKey;
import org.zoxweb.shared.security.SubjectIDDAO;
import org.zoxweb.shared.security.shiro.ShiroRealmStore;
import org.zoxweb.shared.util.ResourceManager;
import org.zoxweb.shared.util.ResourceManager.Resource;
import org.zoxweb.shared.util.SharedStringUtil;

import java.util.Set;

public class XlogistXShiroRealm
    extends AuthorizingRealm

{

	public static final LogWrapper log = new LogWrapper(XlogistXShiroRealm.class).setEnabled(false);

	protected boolean permissionsLookupEnabled = false;
	private boolean cachePersistenceEnabled = false;



	private ShiroRealmStore shiroStore = null;
	
	private APISecurityManager<Subject> apiSecurityManager;
	
	
	public APISecurityManager<Subject> getAPISecurityManager() {
		return apiSecurityManager != null ? apiSecurityManager :  ResourceManager.lookupResource(Resource.API_SECURITY_MANAGER);
	}

	public void setAPISecurityManager(APISecurityManager<Subject> apiSecurityManager) {
		this.apiSecurityManager = apiSecurityManager;
	}

	

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals)
    {
       //null usernames are invalid
       if (principals == null)
       {
           throw new AuthorizationException("PrincipalCollection method argument cannot be null.");
       }
       
       if(log.isEnabled()) log.getLogger().info("PrincipalCollection class:" + principals.getClass());

       if (principals instanceof DomainPrincipalCollection)
       {
	        String userID = (String) getAvailablePrincipal(principals);
	        String domainID   = ((DomainPrincipalCollection) principals).getDomainID();
	        Set<String> roleNames = shiroStore.getSubjectRoles(domainID, userID);
	        Set<String> permissions = null;
	         
	        if (isPermissionsLookupEnabled())
	        {
	        	permissions = shiroStore.getSubjectPermissions(domainID, userID, roleNames);
	        }



	        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo(roleNames);
	        info.setStringPermissions(permissions);

	        return info;
       }

       throw new AuthorizationException("Not a domain info");
	}
	
	
	protected Object getAuthenticationCacheKey(AuthenticationToken token) {
		//if(log.isEnabled()) log.getLogger().info("TAG1::key:" + token);
		if(token instanceof JWTAuthenticationToken)
		{
			return ((JWTAuthenticationToken)token).getJWTSubjectID();
		}
		return super.getAuthenticationCacheKey(token);
    }
	
	 protected Object getAuthenticationCacheKey(PrincipalCollection principals)
	 {
		 //if(log.isEnabled()) log.getLogger().info("TAG2::key:" + principals);
		 if (principals instanceof DomainPrincipalCollection)
		 {
				DomainPrincipalCollection dpc = (DomainPrincipalCollection)principals;
				return dpc.getJWSubjectID() != null ? dpc.getJWSubjectID() : dpc.getPrimaryPrincipal();
		 }
		 return super.getAuthenticationCacheKey(principals);
	  }
	
	
	protected Object getAuthorizationCacheKey(PrincipalCollection principals)
	{
		//if(log.isEnabled()) log.getLogger().info("TAG3:" + principals + " " + principals.getClass());
		if (principals instanceof DomainPrincipalCollection)
		{
			DomainPrincipalCollection dpc = (DomainPrincipalCollection)principals;
			return dpc.getJWSubjectID() != null ? dpc.getJWSubjectID() : dpc.getPrimaryPrincipal();
		}
		return super.getAuthorizationCacheKey(principals);
    }

	/**
	 * @see org.apache.shiro.realm.AuthenticatingRealm#doGetAuthenticationInfo(AuthenticationToken)
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
			throws AuthenticationException
	{
		//if(log.isEnabled()) log.getLogger().info("AuthenticationToken:" + token);
		
		if (token instanceof DomainUsernamePasswordToken)
		{
			//if(log.isEnabled()) log.getLogger().info("DomainUsernamePasswordToken based authentication");
			DomainUsernamePasswordToken dupToken = (DomainUsernamePasswordToken) token;
	        //String userName = upToken.getUsername();
	        //String domainID = upToken.getDomainID();
	        if (dupToken.getUsername() == null)
	        {
	            throw new AccountException("Null usernames are not allowed by this realm.");
	        }
	        SubjectIDDAO userIDDAO = shiroStore.lookupSubjectID(dupToken.getUsername(), "_id", "_user_id");
	        if (userIDDAO == null)
	        {
	            throw new AccountException("Account not found usernames are not allowed by this realm.");
	        }
	        dupToken.setUserID(userIDDAO.getSubjectID());
	        // String userID = upToken.getUserID();
	        //if(log.isEnabled()) log.getLogger().info( dupToken.getUsername() +":"+dupToken.getUserID());
	        // Null username is invalid
	        
	        PasswordDAO password = shiroStore.getSubjectPassword(null, dupToken.getUsername());
	        if (password == null)
	        {
	        	throw new UnknownAccountException("No account found for user [" + dupToken.getUserID() + "]");
	        }
	        
	        String realm = getName();

	        return new DomainAuthenticationInfo(dupToken.getUsername(), dupToken.getUserID(), password, realm, dupToken.getDomainID(), dupToken.getAppID(), null);
	    }
		else if (token instanceof JWTAuthenticationToken)
		{
			//if(log.isEnabled()) log.getLogger().info("JWTAuthenticationToken based authentication");
			// lookup AppDeviceDAO or SubjectAPIKey
			// in oder to do that we need to switch the user to SUPER_ADMIN or DAEMON user
			JWTAuthenticationToken jwtAuthToken = (JWTAuthenticationToken) token;
			SubjectSwap ss = null;
			try
			{
				APISecurityManager<Subject> sm = ResourceManager.lookupResource(Resource.API_SECURITY_MANAGER);
				APIAppManager appManager =  ResourceManager.lookupResource(Resource.API_APP_MANAGER);
				
				ss = new SubjectSwap(sm.getDaemonSubject());
				SubjectAPIKey sak = appManager.lookupSubjectAPIKey(jwtAuthToken.getJWTSubjectID(), false);
				if (sak == null)
					throw new UnknownAccountException("No account found for user [" + jwtAuthToken.getJWTSubjectID() + "]");
				UserIDDAO userIDDAO = shiroStore.lookupUserID(sak.getUserID(), "_id", "_user_id", "primary_email");
			    if (userIDDAO == null)
			    {
			        throw new AccountException("Account not found usernames are not allowed by this realm.");
			    }
			    
			    // set the actual user 
			    jwtAuthToken.setSubjectID(userIDDAO.getSubjectID());
			    
			    String domainID = jwtAuthToken.getDomainID();
			    String appID    = jwtAuthToken.getAppID();
			    if (sak instanceof AppDeviceDAO)
			    {
			    	domainID = ((AppDeviceDAO) sak).getDomainID();
				    appID    = ((AppDeviceDAO) sak).getAppID();
			    }
			    
			    DomainAuthenticationInfo ret =  new DomainAuthenticationInfo(jwtAuthToken.getSubjectID(), sak.getUserID(), sak //sak.getAPIKeyAsBytes()
			    		, getName(), domainID, appID, jwtAuthToken.getJWTSubjectID());
			    
			    return ret;
			}
			catch(Exception e)
			{
				e.printStackTrace();
			}
			finally
			{
				IOUtil.close(ss);
			}
			
			
		}
		 throw new AuthenticationException("Invalid Authentication Token");
	}
	


	public boolean isPermissionsLookupEnabled()
	{
		return permissionsLookupEnabled;
	}

	public void setPermissionsLookupEnabled(boolean permissionsLookupEnabled)
    {
		this.permissionsLookupEnabled = permissionsLookupEnabled;
	}
	
	


	



	


	


	


	


	

	
	public AuthorizationInfo lookupAuthorizationInfo(PrincipalCollection principals)
	{
		return getAuthorizationInfo(principals);
	}
	

	
	
	

	
	
//	protected void clearUserCache(String userSubjectID)
//	{
//		if (userSubjectID != null)
//		{
//			UserIDDAO userID = lookupUserID(userSubjectID);
//			if (userID != null)
//			{
//				if(log.isEnabled()) log.getLogger().info("we must clear the autorizationinfo of " + userID.getPrimaryEmail());
//				SimplePrincipalCollection principals = new SimplePrincipalCollection(userID.getPrimaryEmail(), getName());
//				clearCachedAuthenticationInfo(principals);
//				clearCachedAuthorizationInfo(principals);
//			}
//		}
//	}
	
	 protected void doClearCache(PrincipalCollection principals)
	 {	
		 if (!isCachePersistenceEnabled())
		 {
			 if(log.isEnabled()) log.getLogger().info("principal to clear:" + principals);
			 super.doClearCache(principals);
		 }
		 
		 
//		 if(!isAuthenticationCachingEnabled())
//		 { 
//			 if(log.isEnabled()) log.getLogger().info("isAuthenticationCachingEnabled is no enabled for:" + principals);
//			 clearCachedAuthenticationInfo(principals);
//		 }
//		 else
//		 {
//			 if(log.isEnabled()) log.getLogger().info("isAuthenticationCaching not cleared");
//		 }
//		 if(!isAuthorizationCachingEnabled())
//		 {
//			 clearCachedAuthorizationInfo(principals);
//			 if(log.isEnabled()) log.getLogger().info("isAuthorizationCachingEnabled is no enabled for:" + principals);
//		 }
//		 else
//		 {
//			 if(log.isEnabled()) log.getLogger().info("isAuthorizationCaching not cleared");
//		 }
	 }
	 
	 
	 public void invalidate(String resourceID)
	 {
		 //if(log.isEnabled()) log.getLogger().info("start for:" + resourceID);
		 if (!SharedStringUtil.isEmpty(resourceID))
		 {
			 // check it is a subject key id
			 
			SubjectSwap ss = null;
			SimplePrincipalCollection principalCollection = null;
			try
			{
				//if(log.isEnabled()) log.getLogger().info("ResourceID:" + resourceID);
				APISecurityManager<Subject> sm = ResourceManager.lookupResource(Resource.API_SECURITY_MANAGER);
				APIAppManager appManager =  ResourceManager.lookupResource(Resource.API_APP_MANAGER);
				// try subject api key first
				if (sm != null && appManager != null)
				{
					ss = new SubjectSwap(sm.getDaemonSubject());
					SubjectAPIKey sak = appManager.lookupSubjectAPIKey(resourceID, false);
					if (sak != null)
					{
						UserIDDAO userIDDAO = shiroStore.lookupUserID(sak.getUserID(), "_id", "_user_id", "primary_email");
						if (userIDDAO != null)
						{
							//if(log.isEnabled()) log.getLogger().info("We have a subject api key:" + sak.getSubjectID());
							principalCollection = new DomainPrincipalCollection(userIDDAO.getSubjectID(), null, getName(), null, null, sak.getSubjectID());
						}
					}
				}
				
				// try user
				if (principalCollection == null)
				{
					UserIDDAO userIDDAO = shiroStore.lookupUserID(resourceID, "_id", "_user_id", "primary_email");
					if (userIDDAO != null)
					{
						//if(log.isEnabled()) log.getLogger().info("We have a user:" + userIDDAO.getSubjectID());
						principalCollection = new DomainPrincipalCollection(userIDDAO.getSubjectID(), null, getName(), null, null, null);
					}
				}
			}
			catch(Exception e)
			{
				e.printStackTrace();
			}
			finally
			{
				IOUtil.close(ss);
			}
			 
			if (principalCollection != null)
			{
				if(log.isEnabled()) log.getLogger().info("clearing cached data for:" + principalCollection);
				clearCachedAuthenticationInfo(principalCollection);
				clearCachedAuthorizationInfo(principalCollection);
			}
			else
			{
				if(log.isEnabled()) log.getLogger().info("NOT FOUND!!:" + resourceID);
			}
			 // or user id
		 }
	 }

	public boolean isCachePersistenceEnabled() {
		return cachePersistenceEnabled;
	}

	public void setCachePersistenceEnabled(boolean sessionLessModeEnabled) {
		this.cachePersistenceEnabled = sessionLessModeEnabled;
	}

	public ShiroRealmStore getShiroRealmStore()
	{
		return shiroStore;
	}

	public synchronized void setShiroRealmStore(ShiroRealmStore shiroRealmStore)
	{
		this.shiroStore = shiroRealmStore;
	}
}