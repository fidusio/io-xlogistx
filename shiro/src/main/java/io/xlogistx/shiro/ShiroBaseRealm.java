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
import org.zoxweb.server.api.APIAppManagerProvider;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.api.APIAppManager;
import org.zoxweb.shared.api.APIDataStore;
import org.zoxweb.shared.api.APIException;
import org.zoxweb.shared.api.APISecurityManager;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.data.AppDeviceDAO;
import org.zoxweb.shared.data.UserIDDAO;
import org.zoxweb.shared.db.QueryMatchString;
import org.zoxweb.shared.security.AccessException;
import org.zoxweb.shared.security.CredentialInfo;
import org.zoxweb.shared.security.SubjectAPIKey;
import org.zoxweb.shared.security.SubjectIdentifier;
import org.zoxweb.shared.security.shiro.*;
import org.zoxweb.shared.util.*;
import org.zoxweb.shared.util.Const.RelationalOperator;
import org.zoxweb.shared.util.ResourceManager.Resource;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public abstract class ShiroBaseRealm
    extends AuthorizingRealm
    implements ShiroRealmStore<AuthorizationInfo, PrincipalCollection>
{

	public static final LogWrapper log = new LogWrapper(ShiroBaseRealm.class).setEnabled(false);

	protected boolean permissionsLookupEnabled = false;
	private boolean cachePersistenceEnabled = false;
	
	private APISecurityManager<Subject, AuthorizationInfo, PrincipalCollection> apiSecurityManager;
	
	
	public APISecurityManager<Subject, AuthorizationInfo, PrincipalCollection> getAPISecurityManager() {
		return apiSecurityManager != null ? apiSecurityManager :  ResourceManager.lookupResource(Resource.API_SECURITY_MANAGER);
	}

	public void setAPISecurityManager(APISecurityManager<Subject, AuthorizationInfo, PrincipalCollection> apiSecurityManager) {
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
	        Set<String> roleNames = getSubjectRoles(domainID, userID);
	        Set<String> permissions = null;
	         
	        if (isPermissionsLookupEnabled())
	        {
	        	permissions = getSubjectPermissions(domainID, userID, roleNames);
	        }

	        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo(roleNames);
	        info.setStringPermissions(permissions);

	        return info;
       }

       throw new AuthorizationException("Not a domain info");
	}

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
			UserIDDAO userIDDAO = lookupUserID(dupToken.getUsername(), "_id", "_subject_guid");
			if (userIDDAO == null)
			{
				throw new AccountException("Account not found usernames are not allowed by this realm.");
			}
			dupToken.setSubjectGUID(userIDDAO.getSubjectID());
			// String userID = upToken.getUserID();
			//if(log.isEnabled()) log.getLogger().info( dupToken.getUsername() +":"+dupToken.getUserID());
			// Null username is invalid

			CIPassword password = lookupCredential(dupToken.getUsername(), CredentialInfo.CredentialType.PASSWORD);
			if (password == null)
			{
				throw new UnknownAccountException("No account found for user [" + dupToken.getSubjectGUID() + "]");
			}

			String realm = getName();

			return new DomainAuthenticationInfo(dupToken.getUsername(), dupToken.getSubjectGUID(), password, realm, dupToken.getDomainID(), dupToken.getAppID(), null);
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
				APISecurityManager<Subject, AuthorizationInfo, PrincipalCollection> sm = ResourceManager.lookupResource(Resource.API_SECURITY_MANAGER);
				APIAppManager appManager =  ResourceManager.lookupResource(Resource.API_APP_MANAGER);

				ss = new SubjectSwap(sm.getDaemonSubject());
				// Todo to be fixed
				SubjectAPIKey sak = null;//appManager.lookupSubjectAPIKey(jwtAuthToken.getJWTSubjectID(), false);
				if (sak == null)
					throw new UnknownAccountException("No account found for user [" + jwtAuthToken.getJWTSubjectID() + "]");
				UserIDDAO userIDDAO = lookupUserID(sak.getSubjectGUID(), "_id", "subject_guid", "primary_email");
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

				DomainAuthenticationInfo ret =  new DomainAuthenticationInfo(jwtAuthToken.getSubjectID(), sak.getSubjectID(), sak //sak.getAPIKeyAsBytes()
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






	public boolean isPermissionsLookupEnabled()
	{
		return permissionsLookupEnabled;
	}

	public void setPermissionsLookupEnabled(boolean permissionsLookupEnabled)
    {
		this.permissionsLookupEnabled = permissionsLookupEnabled;
	}
	
	

	public SubjectIdentifier addSubject(SubjectIdentifier subject)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}


	public SubjectIdentifier deleteSubject(SubjectIdentifier subject, boolean withRoles)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}


	public SubjectIdentifier updateSubject(SubjectIdentifier subject)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ShiroRole addRole(ShiroRole role)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		
//		if (role.getPermissions() != null)
//		{
//			for(NVEntity nve : (NVEntity[])role.getPermissions().values())
//			{
//				ShiroPermission existingPerm = lookupPermission(((ShiroPermission)nve).getSubjectID());
//				if (existingPerm != null)
//				{
//					
//				}
//			}
//		}
		
		
		return getAPIDataStore().insert(role);
	}

	
	public ShiroRole deleteRole(ShiroRole role, boolean withPermissions)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		getAPIDataStore().delete(ShiroRole.NVC_SHIRO_ROLE, new QueryMatchString(RelationalOperator.EQUAL, role.getSubjectGUID(), MetaToken.SUBJECT_GUID));
		return role;
	}

	
	public ShiroRole updateRole(ShiroRole role)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return getAPIDataStore().update(role);
	}

	
	public ShiroRoleGroup addRoleGroup(ShiroRoleGroup rolegroup)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public ShiroRoleGroup deleteRoleGroup(ShiroRoleGroup rolegroup)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ShiroRoleGroup updateRoleGroup(ShiroRoleGroup rolegroup)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ShiroPermission addPermission(ShiroPermission permission)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return getAPIDataStore().insert(permission);
	}

	
	public ShiroPermission deletePermission(ShiroPermission permission)
			throws NullPointerException, IllegalArgumentException, AccessException {
		getAPIDataStore().delete(ShiroPermission.NVC_SHIRO_PERMISSION, new QueryMatchString(RelationalOperator.EQUAL, permission.getSubjectGUID(), MetaToken.SUBJECT_GUID));
		return permission;
	}

	
	public ShiroPermission updatePermission(ShiroPermission permission)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return getAPIDataStore().update(permission);
	}

	
	public ArrayList<SubjectIdentifier> getAllSubjects() throws AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ArrayList<ShiroRole> getAllShiroRoles() throws AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ArrayList<ShiroRoleGroup> getAllShiroRoleGroups() throws AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ArrayList<ShiroPermission> getAllShiroPermissions() throws AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	


	
//	public ShiroCollectionAssociationDAO lookupShiroCollection(ShiroBase shiroDao, ShiroAssociationType sat)
//			throws NullPointerException, IllegalArgumentException, AccessException {
//		// TODO Auto-generated method stub
//		return null;
//	}

	
	public ShiroAssociation addShiroAssociation(ShiroAssociation association)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ShiroAssociation removeShiroAssociation(ShiroAssociation association)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	public ShiroPermission lookupPermission(String permissionID)
			throws NullPointerException, IllegalArgumentException, AccessException
	{
		SharedUtil.checkIfNulls("Null permission id", permissionID);
			
		List<ShiroPermission> ret = null;
		if (getAPIDataStore().isValidReferenceID(permissionID))
		{
			ret = getAPIDataStore().search(ShiroPermission.NVC_SHIRO_PERMISSION, null, new QueryMatchString(RelationalOperator.EQUAL, permissionID, MetaToken.REFERENCE_ID));
		}
		else
		{
			// this is wrong fix later
			ret = getAPIDataStore().search(ShiroPermission.NVC_SHIRO_PERMISSION, null, new QueryMatchString(RelationalOperator.EQUAL, permissionID, MetaToken.SUBJECT_GUID));
		}
		
		if (ret != null && ret.size() == 1)
		{
			return ret.get(0);
		}
		return null;
	}
	
	
	public ShiroRole lookupRole(String roleID)
			throws NullPointerException, IllegalArgumentException, AccessException
	{
		SharedUtil.checkIfNulls("Null permission id", roleID);
		if(log.isEnabled()) log.getLogger().info("RoleID:" + roleID);
		
		List<ShiroRole> ret = null;
		if (getAPIDataStore().isValidReferenceID(roleID))
		{
			ret = getAPIDataStore().search(ShiroRole.NVC_SHIRO_ROLE, null, new QueryMatchString(RelationalOperator.EQUAL, roleID, MetaToken.REFERENCE_ID));
		}
		else
		{
			// Todo this is wrong
			ret = getAPIDataStore().search(ShiroRole.NVC_SHIRO_ROLE, null, new QueryMatchString(RelationalOperator.EQUAL, roleID, MetaToken.SUBJECT_GUID));
		}
		
		if (ret != null && ret.size() == 1)
		{
			if(log.isEnabled()) log.getLogger().info("Role found " + ret);
			return ret.get(0);
		}
		if(log.isEnabled()) log.getLogger().info("Role not found");
		return null;
	}
	
	public abstract APIDataStore<?> getAPIDataStore();
	
	public AuthorizationInfo lookupAuthorizationInfo(PrincipalCollection principals)
	{
		return getAuthorizationInfo(principals);
	}
	
	public  UserIDDAO lookupUserID(String subjectID, String...params)
			throws NullPointerException, IllegalArgumentException, AccessException, APIException
	{
		return APIAppManagerProvider.lookupUserID(getAPIDataStore(), subjectID, params);
	}
	
	public  UserIDDAO lookupUserID(GetValue<String> subjectID, String...params)
			throws NullPointerException, IllegalArgumentException, AccessException
	{
		SharedUtil.checkIfNulls("DB or user ID null", subjectID, subjectID.getValue());
		return lookupUserID(subjectID.getValue(), params);
	}



	/**
	 * @param subjectID
	 * @return
	 * @throws NullPointerException
	 * @throws IllegalArgumentException
	 * @throws AccessException
	 */
	@Override
	public SubjectIdentifier lookupSubjectIdentifier(String subjectID)
			throws NullPointerException, IllegalArgumentException, AccessException {
		UserIDDAO userID = lookupUserID(subjectID);
		if(userID != null)
		{
			SubjectIdentifier subjectIdentifier = new SubjectIdentifier();
			subjectIdentifier.setReferenceID(userID.getReferenceID());
			subjectIdentifier.setSubjectType(BaseSubjectID.SubjectType.USER);
			subjectIdentifier.setSubjectID(userID.getSubjectID());
			subjectIdentifier.setSubjectGUID(userID.getSubjectGUID());
			subjectIdentifier.setGUID(userID.getGUID());
			subjectIdentifier.getProperties().add("user_info", userID.getUserInfo());
			return subjectIdentifier;

		}
		return null;
	}

	
	public abstract Set<String> getRecursiveNVEReferenceIDFromForm(String formReferenceID);
	
	
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
				APISecurityManager<Subject, AuthorizationInfo, PrincipalCollection> sm = ResourceManager.lookupResource(Resource.API_SECURITY_MANAGER);
				APIAppManager appManager =  ResourceManager.lookupResource(Resource.API_APP_MANAGER);
				// try subject api key first
				if (sm != null && appManager != null)
				{
					ss = new SubjectSwap(sm.getDaemonSubject());
					// Todo to be fixed
					SubjectAPIKey sak = null;//appManager.lookupSubjectAPIKey(resourceID, false);
					if (sak != null)
					{
						UserIDDAO userIDDAO = lookupUserID(sak.getSubjectGUID(), "_id", "subject_guid", "primary_email");
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
					UserIDDAO userIDDAO = lookupUserID(resourceID, "_id", "_subject_guid", "primary_email");
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
	 
}