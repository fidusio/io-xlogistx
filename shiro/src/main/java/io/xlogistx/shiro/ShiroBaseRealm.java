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
import io.xlogistx.shiro.authz.AuthorizationInfoLookup;
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
import org.zoxweb.shared.crypto.PasswordDAO;
import org.zoxweb.shared.data.AppDeviceDAO;
import org.zoxweb.shared.data.AppIDDAO;
import org.zoxweb.shared.data.UserIDDAO;
import org.zoxweb.shared.db.QueryMatchString;
import org.zoxweb.shared.security.AccessException;
import org.zoxweb.shared.security.SubjectAPIKey;
import org.zoxweb.shared.security.SubjectIDDAO;
import org.zoxweb.shared.security.shiro.*;
import org.zoxweb.shared.util.*;
import org.zoxweb.shared.util.Const.RelationalOperator;
import org.zoxweb.shared.util.ResourceManager.Resource;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public abstract class ShiroBaseRealm
    extends AuthorizingRealm
    implements ShiroRealmStore, AuthorizationInfoLookup
{

	public static final LogWrapper log = new LogWrapper(ShiroBaseRealm.class).setEnabled(false);

	protected boolean permissionsLookupEnabled = false;
	private boolean cachePersistenceEnabled = false;
	
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
			UserIDDAO userIDDAO = lookupUserID(dupToken.getUsername(), "_id", "_user_id");
			if (userIDDAO == null)
			{
				throw new AccountException("Account not found usernames are not allowed by this realm.");
			}
			dupToken.setUserID(userIDDAO.getUserID());
			// String userID = upToken.getUserID();
			//if(log.isEnabled()) log.getLogger().info( dupToken.getUsername() +":"+dupToken.getUserID());
			// Null username is invalid

			PasswordDAO password = getSubjectPassword(null, dupToken.getUsername());
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
				UserIDDAO userIDDAO = lookupUserID(sak.getUserID(), "_id", "_user_id", "primary_email");
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
	
	

	public ShiroSubject addSubject(ShiroSubject subject)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}


	public ShiroSubject deleteSubject(ShiroSubject subject, boolean withRoles)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}


	public ShiroSubject updateSubject(ShiroSubject subject)
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
		getAPIDataStore().delete(ShiroRole.NVC_SHIRO_ROLE, new QueryMatchString(RelationalOperator.EQUAL, role.getSubjectID(), AppIDDAO.Param.SUBJECT_ID));
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
		getAPIDataStore().delete(ShiroPermission.NVC_SHIRO_PERMISSION, new QueryMatchString(RelationalOperator.EQUAL, permission.getSubjectID(),AppIDDAO.Param.SUBJECT_ID));
		return permission;
	}

	
	public ShiroPermission updatePermission(ShiroPermission permission)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return getAPIDataStore().update(permission);
	}

	
	public ArrayList<ShiroSubject> getAllShiroSubjects() throws AccessException {
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

	
	public ShiroSubject lookupSubject(String userName)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
//	public ShiroCollectionAssociationDAO lookupShiroCollection(ShiroBase shiroDao, ShiroAssociationType sat)
//			throws NullPointerException, IllegalArgumentException, AccessException {
//		// TODO Auto-generated method stub
//		return null;
//	}

	
	public ShiroAssociationDAO addShiroAssociation(ShiroAssociationDAO association)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ShiroAssociationDAO removeShiroAssociation(ShiroAssociationDAO association)
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
			ret = getAPIDataStore().search(ShiroPermission.NVC_SHIRO_PERMISSION, null, new QueryMatchString(RelationalOperator.EQUAL, permissionID, AppIDDAO.Param.SUBJECT_ID));
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
			ret = getAPIDataStore().search(ShiroRole.NVC_SHIRO_ROLE, null, new QueryMatchString(RelationalOperator.EQUAL, roleID, AppIDDAO.Param.SUBJECT_ID));
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
	 * @param params
	 * @return
	 * @throws NullPointerException
	 * @throws IllegalArgumentException
	 * @throws AccessException
	 */
	@Override
	public SubjectIDDAO lookupSubjectID(GetValue<String> subjectID, String... params)
			throws NullPointerException, IllegalArgumentException, AccessException {
		return lookupSubjectID(subjectID.getValue(), params);
	}

	/**
	 * @param subjectID
	 * @param params
	 * @return
	 * @throws NullPointerException
	 * @throws IllegalArgumentException
	 * @throws AccessException
	 */
	@Override
	public SubjectIDDAO lookupSubjectID(String subjectID, String... params)
			throws NullPointerException, IllegalArgumentException, AccessException {
		UserIDDAO userID = lookupUserID(subjectID, params);
		if(userID != null)
		{
			SubjectIDDAO subjectIDDAO = new SubjectIDDAO();
			subjectIDDAO.setReferenceID(userID.getReferenceID());
			subjectIDDAO.setSubjectType(BaseSubjectID.SubjectType.USER);
			subjectIDDAO.setSubjectID(userID.getSubjectID());
			subjectIDDAO.setUserID(userID.getUserID());
			subjectIDDAO.setGlobalID(userID.getGlobalID());
			subjectIDDAO.getProperties().add("user_info", userID.getUserInfo());
			return subjectIDDAO;

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
				APISecurityManager<Subject> sm = ResourceManager.lookupResource(Resource.API_SECURITY_MANAGER);
				APIAppManager appManager =  ResourceManager.lookupResource(Resource.API_APP_MANAGER);
				// try subject api key first
				if (sm != null && appManager != null)
				{
					ss = new SubjectSwap(sm.getDaemonSubject());
					SubjectAPIKey sak = appManager.lookupSubjectAPIKey(resourceID, false);
					if (sak != null)
					{
						UserIDDAO userIDDAO = lookupUserID(sak.getUserID(), "_id", "_user_id", "primary_email");
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
					UserIDDAO userIDDAO = lookupUserID(resourceID, "_id", "_user_id", "primary_email");
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