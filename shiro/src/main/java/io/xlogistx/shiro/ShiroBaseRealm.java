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
import org.zoxweb.shared.security.shiro.*;
import org.zoxweb.shared.util.*;
import org.zoxweb.shared.util.Const.RelationalOperator;
import org.zoxweb.shared.util.ResourceManager.Resource;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

public abstract class ShiroBaseRealm
    extends AuthorizingRealm
    implements ShiroRealmStore
{

	private static final transient Logger log = Logger.getLogger(Const.LOGGER_NAME);

	protected boolean permissionsLookupEnabled = false;
	private boolean cachePersistenceEnabled = false;
	
	private APISecurityManager<Subject> apiSecurityManager;
	
	
	public APISecurityManager<Subject> getAPISecurityManager() {
		return apiSecurityManager != null ? apiSecurityManager :  ResourceManager.SINGLETON.lookup(Resource.API_SECURITY_MANAGER);
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
       
       log.info("PrincipalCollection class:" + principals.getClass());

       if (principals instanceof DomainPrincipalCollection)
       {
	        String userID = (String) getAvailablePrincipal(principals);
	        String domainID   = ((DomainPrincipalCollection) principals).getDomainID();
	        Set<String> roleNames = getUserRoles(domainID, userID);
	        Set<String> permissions = null;
	         
	        if (isPermissionsLookupEnabled())
	        {
	        	permissions = getUserPermissions(domainID, userID, roleNames);
	        }

	        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo(roleNames);
	        info.setStringPermissions(permissions);

	        return info;
       }

       throw new AuthorizationException("Not a domain info");
	}
	
	
	protected Object getAuthenticationCacheKey(AuthenticationToken token) {
		//log.info("TAG1::key:" + token);
		if(token instanceof JWTAuthenticationToken)
		{
			return ((JWTAuthenticationToken)token).getJWTSubjectID();
		}
		return super.getAuthenticationCacheKey(token);
    }
	
	 protected Object getAuthenticationCacheKey(PrincipalCollection principals)
	 {
		 //log.info("TAG2::key:" + principals);
		 if (principals instanceof DomainPrincipalCollection)
		 {
				DomainPrincipalCollection dpc = (DomainPrincipalCollection)principals;
				return dpc.getJWSubjectID() != null ? dpc.getJWSubjectID() : dpc.getPrimaryPrincipal();
		 }
		 return super.getAuthenticationCacheKey(principals);
	  }
	
	
	protected Object getAuthorizationCacheKey(PrincipalCollection principals)
	{
		//log.info("TAG3:" + principals + " " + principals.getClass());
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
		//log.info("AuthenticationToken:" + token);
		
		if (token instanceof DomainUsernamePasswordToken)
		{
			//log.info("DomainUsernamePasswordToken based authentication");
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
	        //log.info( dupToken.getUsername() +":"+dupToken.getUserID());
	        // Null username is invalid
	        
	        PasswordDAO password = getUserPassword(null, dupToken.getUsername());
	        if (password == null)
	        {
	        	throw new UnknownAccountException("No account found for user [" + dupToken.getUserID() + "]");
	        }
	        
	        String realm = getName();

	        return new DomainAuthenticationInfo(dupToken.getUsername(), dupToken.getUserID(), password, realm, dupToken.getDomainID(), dupToken.getAppID(), null);
	    }
		else if (token instanceof JWTAuthenticationToken)
		{
			//log.info("JWTAuthenticationToken based authentication");
			// lookup AppDeviceDAO or SubjectAPIKey
			// in oder to do that we need to switch the user to SUPER_ADMIN or DAEMON user
			JWTAuthenticationToken jwtAuthToken = (JWTAuthenticationToken) token;
			SubjectSwap ss = null;
			try
			{
				APISecurityManager<Subject> sm = ResourceManager.SINGLETON.lookup(Resource.API_SECURITY_MANAGER);
				APIAppManager appManager =  ResourceManager.SINGLETON.lookup(Resource.API_APP_MANAGER);
				
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
	
	protected abstract PasswordDAO getUserPassword(String domainID, String userID);
	protected abstract Set<String> getUserRoles(String domainID, String userID);
	protected abstract Set<String> getUserPermissions(String domainID, String userID, Set<String> roleNames);

	public boolean isPermissionsLookupEnabled()
	{
		return permissionsLookupEnabled;
	}

	public void setPermissionsLookupEnabled(boolean permissionsLookupEnabled)
    {
		this.permissionsLookupEnabled = permissionsLookupEnabled;
	}
	
	

	public ShiroSubjectDAO addSubject(ShiroSubjectDAO subject)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}


	public ShiroSubjectDAO deleteSubject(ShiroSubjectDAO subject, boolean withRoles)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}


	public ShiroSubjectDAO updateSubject(ShiroSubjectDAO subject)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ShiroRoleDAO addRole(ShiroRoleDAO role)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		
//		if (role.getPermissions() != null)
//		{
//			for(NVEntity nve : (NVEntity[])role.getPermissions().values())
//			{
//				ShiroPermissionDAO existingPerm = lookupPermission(((ShiroPermissionDAO)nve).getSubjectID());
//				if (existingPerm != null)
//				{
//					
//				}
//			}
//		}
		
		
		return getAPIDataStore().insert(role);
	}

	
	public ShiroRoleDAO deleteRole(ShiroRoleDAO role, boolean withPermissions)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		getAPIDataStore().delete(ShiroRoleDAO.NVC_SHIRO_ROLE_DAO, new QueryMatchString(RelationalOperator.EQUAL, role.getSubjectID(), AppIDDAO.Param.SUBJECT_ID));
		return role;
	}

	
	public ShiroRoleDAO updateRole(ShiroRoleDAO role)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return getAPIDataStore().update(role);
	}

	
	public ShiroRoleGroupDAO addRoleGroup(ShiroRoleGroupDAO rolegroup)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public ShiroRoleGroupDAO deleteRoleGroup(ShiroRoleGroupDAO rolegroup)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ShiroRoleGroupDAO updateRoleGroup(ShiroRoleGroupDAO rolegroup)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ShiroPermissionDAO addPermission(ShiroPermissionDAO permission)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return getAPIDataStore().insert(permission);
	}

	
	public ShiroPermissionDAO deletePermission(ShiroPermissionDAO permission)
			throws NullPointerException, IllegalArgumentException, AccessException {
		getAPIDataStore().delete(ShiroPermissionDAO.NVC_SHIRO_PERMISSION_DAO, new QueryMatchString(RelationalOperator.EQUAL, permission.getSubjectID(),AppIDDAO.Param.SUBJECT_ID));
		return permission;
	}

	
	public ShiroPermissionDAO updatePermission(ShiroPermissionDAO permission)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return getAPIDataStore().update(permission);
	}

	
	public ArrayList<ShiroSubjectDAO> getAllShiroSubjects() throws AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ArrayList<ShiroRoleDAO> getAllShiroRoles() throws AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ArrayList<ShiroRoleGroupDAO> getAllShiroRoleGroups() throws AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ArrayList<ShiroPermissionDAO> getAllShiroPermissions() throws AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ShiroSubjectDAO lookupSubject(String userName)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
	public ShiroCollectionAssociationDAO lookupShiroCollection(ShiroDAO shiroDao, ShiroAssociationType sat)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return null;
	}

	
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

	public ShiroPermissionDAO lookupPermission(String permissionID)
			throws NullPointerException, IllegalArgumentException, AccessException
	{
		SharedUtil.checkIfNulls("Null permission id", permissionID);
			
		List<ShiroPermissionDAO> ret = null;
		if (getAPIDataStore().isValidReferenceID(permissionID))
		{
			ret = getAPIDataStore().search(ShiroPermissionDAO.NVC_SHIRO_PERMISSION_DAO, null, new QueryMatchString(RelationalOperator.EQUAL, permissionID, MetaToken.REFERENCE_ID));
		}
		else
		{
			ret = getAPIDataStore().search(ShiroPermissionDAO.NVC_SHIRO_PERMISSION_DAO, null, new QueryMatchString(RelationalOperator.EQUAL, permissionID, AppIDDAO.Param.SUBJECT_ID));
		}
		
		if (ret != null && ret.size() == 1)
		{
			return ret.get(0);
		}
		return null;
	}
	
	
	public ShiroRoleDAO lookupRole(String roleID)
			throws NullPointerException, IllegalArgumentException, AccessException
	{
		SharedUtil.checkIfNulls("Null permission id", roleID);
		log.info("RoleID:" + roleID);
		
		List<ShiroRoleDAO> ret = null;
		if (getAPIDataStore().isValidReferenceID(roleID))
		{
			ret = getAPIDataStore().search(ShiroRoleDAO.NVC_SHIRO_ROLE_DAO, null, new QueryMatchString(RelationalOperator.EQUAL, roleID, MetaToken.REFERENCE_ID));
		}
		else
		{
			ret = getAPIDataStore().search(ShiroRoleDAO.NVC_SHIRO_ROLE_DAO, null, new QueryMatchString(RelationalOperator.EQUAL, roleID, AppIDDAO.Param.SUBJECT_ID));
		}
		
		if (ret != null && ret.size() == 1)
		{
			log.info("Role found " + ret);
			return ret.get(0);
		}
		log.info("Role not found");
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
	
	
	
	public abstract Set<String> getRecusiveNVEReferenceIDFromForm(String formReferenceID);
	
	
//	protected void clearUserCache(String userSubjectID)
//	{
//		if (userSubjectID != null)
//		{
//			UserIDDAO userID = lookupUserID(userSubjectID);
//			if (userID != null)
//			{
//				log.info("we must clear the autorizationinfo of " + userID.getPrimaryEmail());
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
			 log.info("principal to clear:" + principals);
			 super.doClearCache(principals);
		 }
		 
		 
//		 if(!isAuthenticationCachingEnabled())
//		 { 
//			 log.info("isAuthenticationCachingEnabled is no enabled for:" + principals);
//			 clearCachedAuthenticationInfo(principals);
//		 }
//		 else
//		 {
//			 log.info("isAuthenticationCaching not cleared");
//		 }
//		 if(!isAuthorizationCachingEnabled())
//		 {
//			 clearCachedAuthorizationInfo(principals);
//			 log.info("isAuthorizationCachingEnabled is no enabled for:" + principals);
//		 }
//		 else
//		 {
//			 log.info("isAuthorizationCaching not cleared");
//		 }
	 }
	 
	 
	 public void invalidate(String resourceID)
	 {
		 //log.info("start for:" + resourceID);
		 if (!SharedStringUtil.isEmpty(resourceID))
		 {
			 // check it is a subject key id
			 
			SubjectSwap ss = null;
			SimplePrincipalCollection principalCollection = null;
			try
			{
				//log.info("ResourceID:" + resourceID);
				APISecurityManager<Subject> sm = ResourceManager.SINGLETON.lookup(Resource.API_SECURITY_MANAGER);
				APIAppManager appManager =  ResourceManager.SINGLETON.lookup(Resource.API_APP_MANAGER);
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
							//log.info("We have a subject api key:" + sak.getSubjectID());
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
						//log.info("We have a user:" + userIDDAO.getSubjectID());
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
				log.info("clearing cached data for:" + principalCollection);
				clearCachedAuthenticationInfo(principalCollection);
				clearCachedAuthorizationInfo(principalCollection);
			}
			else
			{
				log.info("NOT FOUND!!:" + resourceID);
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