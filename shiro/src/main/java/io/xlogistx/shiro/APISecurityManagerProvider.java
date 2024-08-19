package io.xlogistx.shiro;


import io.xlogistx.shiro.authc.JWTAuthenticationToken;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.UnavailableSecurityManagerException;
import org.apache.shiro.subject.Subject;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.security.KeyMakerProvider;
import org.zoxweb.shared.api.APICredentialsDAO;
import org.zoxweb.shared.api.APIDataStore;
import org.zoxweb.shared.api.APISecurityManager;
import org.zoxweb.shared.api.APITokenDAO;
import org.zoxweb.shared.crypto.EncryptedDAO;
import org.zoxweb.shared.crypto.EncryptedKeyDAO;
import org.zoxweb.shared.crypto.PasswordDAO;
import org.zoxweb.shared.data.DataConst.SessionParam;
import org.zoxweb.shared.data.MessageTemplateDAO;
import org.zoxweb.shared.data.UserIDDAO;
import org.zoxweb.shared.db.QueryMarker;
import org.zoxweb.shared.filters.BytesValueFilter;
import org.zoxweb.shared.filters.ChainedFilter;
import org.zoxweb.shared.filters.FilterType;
import org.zoxweb.shared.security.AccessException;
import org.zoxweb.shared.security.JWTToken;
import org.zoxweb.shared.security.SubjectIdentifier;
import org.zoxweb.shared.security.model.SecurityModel;
import org.zoxweb.shared.security.shiro.*;
import org.zoxweb.shared.util.*;
import org.zoxweb.shared.util.Const.LogicalOperator;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;


public class APISecurityManagerProvider
	implements  APISecurityManager<Subject>
{
	
	public static final LogWrapper log = new LogWrapper(APISecurityManagerProvider.class);
	
	private final AtomicReference<Subject> daemon = new AtomicReference<Subject>();
	

	@Override
	public final Object encryptValue(APIDataStore<?> dataStore, NVEntity container, NVConfig nvc, NVBase<?> nvb, byte[] msKey)
			throws NullPointerException, IllegalArgumentException, AccessException {
		SharedUtil.checkIfNulls("Null parameters", container != null ? container.getReferenceID() : container, nvb);
		
		
		
		boolean encrypt = false;
		
//		System.out.println("NVC:"+nvc);
//		System.out.println("NVB:"+nvb);
		
		// the nvpair filter will override nvc value
		if (nvb instanceof NVPair && 
			(ChainedFilter.isFilterSupported(((NVPair)nvb).getValueFilter(),FilterType.ENCRYPT) || ChainedFilter.isFilterSupported(((NVPair)nvb).getValueFilter(),FilterType.ENCRYPT_MASK)))
		{
			encrypt = true;
			
			//System.out.println("NVB Filter:"+((NVPair)nvb).getValueFilter().toCanonicalID());
		}
		else if (nvc != null && (ChainedFilter.isFilterSupported(nvc.getValueFilter(), FilterType.ENCRYPT) || ChainedFilter.isFilterSupported(nvc.getValueFilter(), FilterType.ENCRYPT_MASK)))
		{
			encrypt = true;
			//System.out.println("NVC Filter:"+nvc.getValueFilter());
		}
		
		
		
//		System.out.println("NVC:"+nvc);
//		System.out.println("NVB:"+nvb);
//		System.out.println("Encrypt:"+encrypt);
		
		if (encrypt && nvb.getValue() != null)
		{
//			CRUD toCheck [] = null;
//			if (container.getReferenceID() != null)
//			{
//				toCheck = new CRUD[]{CRUD.UPDATE};
//			}
//			else
//			{
//				toCheck = new CRUD[]{CRUD.CREATE, CRUD.UPDATE};
//			}
			
			// CRUD.MOVE was to allow shared with to move the data between folders
			byte dataKey[] = KeyMakerProvider.SINGLETON.getKey(dataStore, msKey, checkNVEntityAccess(LogicalOperator.OR, container, CRUD.MOVE, CRUD.UPDATE, CRUD.CREATE), container.getReferenceID());
			try
			{
				return CryptoUtil.encryptDAO(new EncryptedDAO(), dataKey, BytesValueFilter.SINGLETON.validate(nvb));
				
			} catch (InvalidKeyException | NullPointerException
					| IllegalArgumentException | NoSuchAlgorithmException
					| NoSuchPaddingException
					| InvalidAlgorithmParameterException
					| IllegalBlockSizeException | BadPaddingException e)
			{
				// TODO Auto-generated catch block
				throw new AccessException(e.getMessage());
			}
		}
		else
		{
			return nvb.getValue();
		}
	}
	
	
	protected ShiroBaseRealm getShiroBaseRealm()
	{
		return ShiroUtil.getRealm(ShiroBaseRealm.class);
	}

	@SuppressWarnings("unchecked")
	@Override
	public final NVEntity decryptValues(APIDataStore<?> dataStore, NVEntity container, byte msKey[])
		throws NullPointerException, IllegalArgumentException, AccessException
	{
		
		if (container == null)
		{
			return null;
		}
		
		SharedUtil.checkIfNulls("Null parameters", container != null ? container.getReferenceID() : container);
		for (NVBase<?> nvb : container.getAttributes().values().toArray( new NVBase[0]))
		{
			if (nvb instanceof NVPair)
			{
				decryptValue(dataStore, container, (NVPair)nvb, null);
			}
			else if (nvb instanceof NVEntityReference)
			{
				NVEntity temp = (NVEntity) nvb.getValue();
				if (temp != null)
				{
					decryptValues(dataStore, temp, null);
				}
			}
			else if (nvb instanceof NVEntityReferenceList || nvb instanceof NVEntityReferenceIDMap || nvb instanceof NVEntityGetNameMap)
			{
				ArrayValues<NVEntity> arrayValues = (ArrayValues<NVEntity>) nvb;
				for (NVEntity nve : arrayValues.values())
				{
					if (nve != null)
					{
						decryptValues(dataStore, container, null);
					}
				}
			}
		}
		
		
		return container;
		
	}
	
	@Override
	public final String decryptValue(APIDataStore<?> dataStore, NVEntity container, NVPair nvp, byte msKey[])
			throws NullPointerException, IllegalArgumentException, AccessException
		{
		
			if (container instanceof EncryptedDAO)
			{
				return nvp != null ? nvp.getValue() : null;
			}
		
		
			SharedUtil.checkIfNulls("Null parameters", container != null ? container.getReferenceID() : container, nvp);
			
			if (nvp.getValue()!= null && (ChainedFilter.isFilterSupported(nvp.getValueFilter(), FilterType.ENCRYPT) || ChainedFilter.isFilterSupported(nvp.getValueFilter(), FilterType.ENCRYPT_MASK)))
			{
				
				byte dataKey[] = KeyMakerProvider.SINGLETON.getKey(dataStore, msKey, checkNVEntityAccess(container, CRUD.READ), container.getReferenceID());
				try
				{
					EncryptedDAO ed = EncryptedDAO.fromCanonicalID(nvp.getValue());
					byte data[] = CryptoUtil.decryptEncryptedDAO(ed, dataKey);
					
					nvp.setValue( new String(data, SharedStringUtil.UTF_8));
					return nvp.getValue();
					
					
				} catch (NullPointerException
						| IllegalArgumentException | UnsupportedEncodingException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | SignatureException e)
				{
					// TODO Auto-generated catch block
					throw new AccessException(e.getMessage());
				}
			}
			else
			{
				return nvp.getValue();
			}
		}
	
	
	@Override
	public final Object decryptValue(APIDataStore<?> dataStore, NVEntity container, NVBase<?> nvb, Object value, byte msKey[])
			throws NullPointerException, IllegalArgumentException, AccessException
	{
	
		if (container instanceof EncryptedDAO && !(container instanceof EncryptedKeyDAO))
		{
			container.setValue(nvb.getName(), value);
			return nvb.getValue();
		}
	
	
		SharedUtil.checkIfNulls("Null parameters", container != null ? container.getReferenceID() : container, nvb);
		NVConfig nvc = ((NVConfigEntity)container.getNVConfig()).lookup(nvb.getName());
		
		if (value instanceof EncryptedDAO && (ChainedFilter.isFilterSupported(nvc.getValueFilter(), FilterType.ENCRYPT) || ChainedFilter.isFilterSupported(nvc.getValueFilter(), FilterType.ENCRYPT_MASK)))
		{
			
			byte dataKey[] = KeyMakerProvider.SINGLETON.getKey(dataStore, msKey, checkNVEntityAccess(container, CRUD.READ), container.getReferenceID());
			try
			{
				
				byte data[] = CryptoUtil.decryptEncryptedDAO((EncryptedDAO) value, dataKey);
				
				BytesValueFilter.setByteArrayToNVBase(nvb, data);
				
			
				return nvb.getValue();
				
				
			} catch (NullPointerException
					| IllegalArgumentException | InvalidKeyException
					| NoSuchAlgorithmException | NoSuchPaddingException
					| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | SignatureException e)
			{
				// TODO Auto-generated catch block
				e.printStackTrace();
				throw new AccessException(e.getMessage());
			}
		}
		else
		{
		
			return value;
		}
	}
	
	@Override
	public final Object decryptValue(String userID, APIDataStore<?> dataStore, NVEntity container, Object value, byte msKey[])
			throws NullPointerException, IllegalArgumentException, AccessException
	{
	
		if (container instanceof EncryptedDAO && !(container instanceof EncryptedKeyDAO))
		{
			
			return value;
		}
	
	
		SharedUtil.checkIfNulls("Null parameters", container != null ? container.getReferenceID() : container);
		
		if (value instanceof EncryptedDAO)
		{
			//if(log.isEnabled()) log.getLogger().info("userID:" + userID);
			
			byte dataKey[] = KeyMakerProvider.SINGLETON.getKey(dataStore, msKey, (userID != null ?  userID : checkNVEntityAccess(container, CRUD.READ)), container.getReferenceID());
			try
			{
				
				byte data[] = CryptoUtil.decryptEncryptedDAO((EncryptedDAO) value, dataKey);
				return BytesValueFilter.bytesToValue(String.class, data);
				
				
			} catch (NullPointerException
					| IllegalArgumentException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | SignatureException e)
			{
				// TODO Auto-generated catch block
				e.printStackTrace();
				throw new AccessException(e.getMessage());
			}
		}
		else
		{
		
			return value;
		}
	}

	@Override
	public final void associateNVEntityToSubjectUserID(NVEntity nve, String userID) {
		// TODO Auto-generated method stub
		if (nve.getReferenceID() == null)
		{
			if (nve.getSubjectGUID() == null)
			{
				if (userID != null)
				try
				{
					SecurityUtils.getSecurityManager();
				}
				catch(UnavailableSecurityManagerException e)
				{
					return;
				}

				/// must create a exclusion filter
				if (!(nve instanceof UserIDDAO || nve instanceof MessageTemplateDAO))
					nve.setSubjectGUID(userID != null ? userID : currentUserID());
				
				for (NVBase<?> nvb : nve.getAttributes().values().toArray( new NVBase[0]))
				{
					if (nvb instanceof NVEntityReference)
					{
						NVEntity temp = (NVEntity) nvb.getValue();
						if (temp != null)
						{
							associateNVEntityToSubjectUserID(temp, userID);
						}
					}
					else if (nvb instanceof NVEntityReferenceList || nvb instanceof NVEntityReferenceIDMap || nvb instanceof NVEntityGetNameMap)
					{
						@SuppressWarnings("unchecked")
						ArrayValues<NVEntity> arrayValues = (ArrayValues<NVEntity>) nvb;
						for (NVEntity nveTemp : arrayValues.values())
						{
							if (nveTemp != null)
							{
								associateNVEntityToSubjectUserID(nveTemp, userID);
							}
						}
					}
				}	
				
			}
		}
	}

	@Override
	public final String currentSubjectID()
			throws AccessException
	{
		// TODO Auto-generated method stub
		return (String) SecurityUtils.getSubject().getPrincipal();
	}
	
	public final String currentDomainID()
			throws AccessException
	{
		return ShiroUtil.subjectDomainID();
	}
	
	public final String currentAppID()
			throws AccessException
	{
		return ShiroUtil.subjectAppID();
	}
	
	
	
	

	@Override
	public final String currentUserID()
			throws AccessException
	{
		// new code
		
		String userID = (String) SecurityUtils.getSubject().getSession().getAttribute(SessionParam.USER_ID.getName());
		if (userID == null)
		{
			userID = ShiroUtil.subjectUserID();
		}
//		try
//		{
//			SecurityUtils.getSecurityManager();
//
//			if (userID == null)
//			{
//				userID = ShiroUtil.subjectUserID();
//			}
//		}
//		catch(UnavailableSecurityManagerException e)
//		{
//		}
		return userID;
	}

	@Override
	public final Subject getDaemonSubject()
	{
		return daemon.get();
	}
	
	
	
	public final void setDaemonSubject(Subject subject)
	{
		if (subject != null && daemon.get() == null)
		{
			if (daemon.get() == null)
			{
				daemon.set(subject);
			}
		}
	}

	@Override
	public final  boolean isNVEntityAccessible(NVEntity nve, CRUD ...permissions)
			throws NullPointerException, IllegalArgumentException
	{
		return isNVEntityAccessible(LogicalOperator.AND, nve, permissions);
	}
	
	@Override
	public final  boolean isNVEntityAccessible(LogicalOperator lo, NVEntity nve, CRUD ...permissions)
		throws NullPointerException, IllegalArgumentException
	{
		try
		{
			checkNVEntityAccess(lo, nve, permissions);
			return true;
		}
		catch(AccessException e)
		{
			//e.printStackTrace();
			return false;
		}
	}
	
	@Override
	public final String checkNVEntityAccess(NVEntity nve, CRUD ...permissions)
			throws NullPointerException, IllegalArgumentException, AccessException
	
	{
		return checkNVEntityAccess(LogicalOperator.AND, nve, permissions);
	}
	
	@Override
	public final String checkNVEntityAccess(LogicalOperator lo, NVEntity nve, CRUD ...permissions)
		throws NullPointerException, IllegalArgumentException, AccessException
	{
		SharedUtil.checkIfNulls("Null NVEntity", lo, nve);
		
		if (nve instanceof APICredentialsDAO || nve instanceof APITokenDAO)
		{
			return nve.getSubjectGUID();
		}
		
		String userID = currentUserID();
		
		if (userID == null || nve.getSubjectGUID() == null)
		{
			throw new AccessException("Unauthenticed subject: " + nve.getClass().getName());
		}
		
		if (!nve.getSubjectGUID().equals(userID))
		{
			
			if (permissions != null && permissions.length > 0)
			{
				boolean checkStatus = false;
				for(CRUD permission : permissions)
				{
					String pattern = SharedUtil.toCanonicalID(':', "nventity", permission, nve.getReferenceID());
					checkStatus = ShiroUtil.isPermitted(pattern);
					if ((checkStatus && LogicalOperator.OR == lo) ||
						(!checkStatus && LogicalOperator.AND == lo))
					{
						// we are ok
						break;
					}
					
				}
				if(checkStatus)
					return nve.getSubjectGUID();
			}
			
			if(log.isEnabled()) log.getLogger().info("nveUserID:" + nve.getSubjectGUID() + " userID:" + userID);
			throw new AccessException("Access Denied. for resource:" + nve.getReferenceID());
		}
		
		return userID;
	}
	
	
	

	@Override
	public final boolean isNVEntityAccessible(String nveRefID, String nveUserID, CRUD... permissions) {
		SharedUtil.checkIfNulls("Null reference ID.", nveRefID);
		
		String userID = currentUserID();
		
		if (userID != null && nveUserID != null)
		{
			if (!nveUserID.equals(userID))
			{
				if (permissions != null && permissions.length > 0)
				{
	
					for(CRUD permission : permissions)
					{
						if (!ShiroUtil.isPermitted(SharedUtil.toCanonicalID(':', "nventity", permission, nveRefID)))
						{
							return false;
						}
					}
					
					return true;
				}
				
				//if(log.isEnabled()) log.getLogger().info("NVEntity UserID:" + nveUserID + " UserID:" + userID);
			}
			else
			{
				return true;
			}
		}
		
		return false;
	}
	
	@Override
	public final void checkSubject(String subjectID)
			throws NullPointerException, AccessException
	{
		SharedUtil.checkIfNulls("subjectID null", subjectID);
		if(!SecurityUtils.getSubject().isAuthenticated() && !SecurityUtils.getSubject().getPrincipal().equals(subjectID))
		{
			throw new AccessException("Access denied");
			
		}
	}
	
	
	@Override
	public final String checkNVEntityAccess(String nveRefID, String nveUserID, CRUD ...permissions)
			throws NullPointerException, IllegalArgumentException, AccessException
	{
		SharedUtil.checkIfNulls("Null reference ID.", nveRefID);
		
		String userID = currentUserID();
		
		if (userID == null || nveUserID == null)
		{
			throw new AccessException("Unauthenticed subject.");
		}
		
		if (!nveUserID.equals(userID))
		{
			if (permissions != null && permissions.length > 0)
			{

				for(CRUD permission : permissions)
				{
					ShiroUtil.checkPermissions(SharedUtil.toCanonicalID(':', "nventity", permission, nveRefID));
				}
				
				return nveUserID;
			}
			
			if(log.isEnabled()) log.getLogger().info("NVEntity UserID:" + nveUserID + " UserID:" + userID);
			
			throw new AccessException("Unauthorized subject");
		}
		
		return userID;
	}
	
	@Override
	public final String checkNVEntityAccess(String nveRefID, CRUD ...permissions)
		throws NullPointerException, IllegalArgumentException, AccessException
	{
		SharedUtil.checkIfNulls("Null reference ID.", nveRefID);
		
		String userID = currentUserID();
		
		if (userID == null)
		{
			throw new AccessException("Unauthenticed subject.");
		}
		
		if (!userID.equals(userID))
		{
			if (permissions != null && permissions.length > 0)
			{

				for(CRUD permission : permissions)
				{
					ShiroUtil.checkPermissions(SharedUtil.toCanonicalID(':', "nventity", permission, nveRefID));
				}
				
				return userID;
			}
			
			if(log.isEnabled()) log.getLogger().info("NVEntity refID:" + nveRefID + " UserID:" + userID);
			
			throw new AccessException("Unauthorized subject");
		}
		
		return userID;
	}

	@Override
	public Subject login(String subjectID, String credentials, String domainID, String appID, boolean autoLogin)
			throws NullPointerException, IllegalArgumentException, AccessException
	{
		return ShiroUtil.loginSubject(subjectID, credentials, domainID, appID, autoLogin);
	}
	
	
	public Subject login(JWTToken jwtToken)
			throws NullPointerException, IllegalArgumentException, AccessException
	{
		Subject currentUser = SecurityUtils.getSubject();
	    if (!currentUser.isAuthenticated())
	    {
	        //collect user principals and credentials in a gui specific manner
	        //such as username/password html form, X509 certificate, OpenID, etc.
	        //We'll use the username/password example here since it is the most common.
	    	
	        currentUser.login(new JWTAuthenticationToken(jwtToken));
	        //if(log.isEnabled()) log.getLogger().info(""+SecurityUtils.getSubject().getPrincipals().getClass());
	    }   
		return currentUser;
	}

	@Override
	public void logout() 
	{
		// TODO Auto-generated method stub
		SecurityUtils.getSubject().logout();
	}

	@Override
	public String currentJWTSubjectID() throws AccessException
	{
		// TODO Auto-generated method stub
		return ShiroUtil.subjectJWTID();
	}



	/**
	 * Add a subject
	 *
	 * @param subject
	 * @return ShiroSubject
	 * @throws NullPointerException
	 * @throws IllegalArgumentException
	 * @throws AccessException
	 */
	@Override
	public SubjectIdentifier addSubject(SubjectIdentifier subject) throws NullPointerException, IllegalArgumentException, AccessException {
		return null;
	}

	@Override
	public SubjectIdentifier deleteSubject(SubjectIdentifier subject, boolean withRoles)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return  getShiroBaseRealm().deleteSubject(subject, withRoles);
	}

	@Override
	public SubjectIdentifier updateSubject(SubjectIdentifier subject)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return  getShiroBaseRealm().updateSubject(subject);
	}

	@Override
	public ShiroRole addRole(ShiroRole role)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		checkPermissions(SecurityModel.Permission.ROLE_ADD.getValue());
		return  getShiroBaseRealm().addRole(role);
	}

	@Override
	public ShiroRole lookupRole(String roleID)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		
		return  getShiroBaseRealm().lookupRole(roleID);
	}

	@Override
	public ShiroRole deleteRole(ShiroRole role, boolean withPermissions)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		checkPermissions(SecurityModel.Permission.ROLE_DELETE.getValue());
		return  getShiroBaseRealm().deleteRole(role, withPermissions);
	}

	@Override
	public ShiroRole updateRole(ShiroRole role)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		checkPermissions(SecurityModel.Permission.ROLE_UPDATE.getValue());
		return  getShiroBaseRealm().updateRole(role);
	}

	@Override
	public ShiroRoleGroup addRoleGroup(ShiroRoleGroup rolegroup)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return  getShiroBaseRealm().addRoleGroup(rolegroup);
	}

	@Override
	public ShiroRoleGroup deleteRoleGroup(ShiroRoleGroup rolegroup)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return  getShiroBaseRealm().deleteRoleGroup(rolegroup);
	}

	@Override
	public ShiroRoleGroup updateRoleGroup(ShiroRoleGroup rolegroup)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return  getShiroBaseRealm().updateRoleGroup(rolegroup);
	}

	@Override
	public ShiroPermission addPermission(ShiroPermission permission)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		checkPermissions(SecurityModel.Permission.PERMISSION_ADD.getValue());
		return  getShiroBaseRealm().addPermission(permission);
	}

	@Override
	public ShiroPermission lookupPermission(String permissionID)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return  getShiroBaseRealm().lookupPermission(permissionID);
	}

	@Override
	public ShiroPermission deletePermission(ShiroPermission permission)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		checkPermissions(SecurityModel.Permission.PERMISSION_DELETE.getValue());
		return  getShiroBaseRealm().deletePermission(permission);
	}

	@Override
	public ShiroPermission updatePermission(ShiroPermission permission)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		checkPermissions(SecurityModel.Permission.PERMISSION_UPDATE.getValue());
		return  getShiroBaseRealm().updatePermission(permission);
	}

	@Override
	public List<SubjectIdentifier> getAllSubjects() throws AccessException {
		// TODO Auto-generated method stub
		return  getShiroBaseRealm().getAllSubjects();
	}

	@Override
	public List<ShiroRole> getAllShiroRoles() throws AccessException {
		// TODO Auto-generated method stub
		return  getShiroBaseRealm().getAllShiroRoles();
	}

	@Override
	public List<ShiroRoleGroup> getAllShiroRoleGroups() throws AccessException {
		// TODO Auto-generated method stub
		return  getShiroBaseRealm().getAllShiroRoleGroups();
	}

	@Override
	public List<ShiroPermission> getAllShiroPermissions() throws AccessException {
		// TODO Auto-generated method stub
		return  getShiroBaseRealm().getAllShiroPermissions();
	}

	@Override
	public SubjectIdentifier lookupSubject(String userName)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return  getShiroBaseRealm().lookupSubject(userName);
	}

//	@Override
//	public ShiroCollectionAssociationDAO lookupShiroCollection(ShiroBase shiroDao, ShiroAssociationType sat)
//			throws NullPointerException, IllegalArgumentException, AccessException {
//		// TODO Auto-generated method stub
//		return  getShiroBaseRealm().lookupShiroCollection(shiroDao, sat);
//	}

	@Override
	public ShiroAssociation addShiroAssociation(ShiroAssociation association)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		
		return getShiroBaseRealm().addShiroAssociation(association);
	}

	@Override
	public ShiroAssociation removeShiroAssociation(ShiroAssociation association)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		
		return  getShiroBaseRealm().removeShiroAssociation(association);
	}

	/**
	 * Get the user password
	 *
	 * @param domainID
	 * @param userID
	 * @return
	 * @throws NullPointerException
	 * @throws IllegalArgumentException
	 * @throws AccessException
	 */
	@Override
	public PasswordDAO getSubjectPassword(String domainID, String userID) throws NullPointerException, IllegalArgumentException, AccessException {
		return null;
	}

	@Override
	public PasswordDAO setSubjectPassword(SubjectIdentifier subject, PasswordDAO passwd) throws NullPointerException, IllegalArgumentException, AccessException {
		return null;
	}

	@Override
	public PasswordDAO setSubjectPassword(String subject, PasswordDAO passwd) throws NullPointerException, IllegalArgumentException, AccessException {
		return null;
	}

	@Override
	public PasswordDAO setSubjectPassword(SubjectIdentifier subject, String passwd) throws NullPointerException, IllegalArgumentException, AccessException {
		return null;
	}

	@Override
	public PasswordDAO setSubjectPassword(String subject, String passwd) throws NullPointerException, IllegalArgumentException, AccessException {
		return null;
	}

	/**
	 * Get the user roles
	 *
	 * @param domainID
	 * @param userID
	 * @return
	 * @throws NullPointerException
	 * @throws IllegalArgumentException
	 * @throws AccessException
	 */
	@Override
	public Set<String> getSubjectRoles(String domainID, String userID) throws NullPointerException, IllegalArgumentException, AccessException {
		return null;
	}

	/**
	 * Get subject permissions
	 *
	 * @param domainID
	 * @param userID
	 * @param roleNames
	 * @return
	 * @throws NullPointerException
	 * @throws IllegalArgumentException
	 * @throws AccessException
	 */
	@Override
	public Set<String> getSubjectPermissions(String domainID, String userID, Set<String> roleNames) throws NullPointerException, IllegalArgumentException, AccessException {
		return null;
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
	public UserIDDAO lookupUserID(GetValue<String> subjectID, String... params) throws NullPointerException, IllegalArgumentException, AccessException {
		return null;
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
	public UserIDDAO lookupUserID(String subjectID, String... params) throws NullPointerException, IllegalArgumentException, AccessException {
		return null;
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
	public SubjectIdentifier lookupSubjectID(GetValue<String> subjectID, String... params) throws NullPointerException, IllegalArgumentException, AccessException {
		return null;
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
	public SubjectIdentifier lookupSubjectID(String subjectID, String... params) throws NullPointerException, IllegalArgumentException, AccessException {
		return null;
	}


	@Override
	public void addShiroRule(ShiroAssociationRule sard) {
		// TODO Auto-generated method stub
		SharedUtil.checkIfNulls("Null ShiroAssociationRule", sard, sard.getAssociationType());
		
		switch(sard.getAssociationType())
		{
		case PERMISSION_TO_ROLE:
			break;
		case PERMISSION_TO_SUBJECT:
			break;
		case ROLEGROUP_TO_SUBJECT:
			break;
		case ROLE_TO_ROLEGROUP:
			break;
		case ROLE_TO_SUBJECT:
			//checkRole()
			break;
		case PERMISSION_TO_RESOURCE:
			break;
		case ROLE_TO_RESOURCE:
			break;
		
		
		}
		getShiroBaseRealm().addShiroRule(sard);
	}


	@Override
	public void deleteShiroRule(ShiroAssociationRule sard)
	{
		// TODO Auto-generated method stub
		
		getShiroBaseRealm().deleteShiroRule(sard);
	}


	@Override
	public void updateShiroRule(ShiroAssociationRule sard) {
		// TODO Auto-generated method stub
		
		getShiroBaseRealm().updateShiroRule(sard);
	}


	@Override
	public List<ShiroAssociationRule> search(QueryMarker... queryCriteria) {
		// TODO Auto-generated method stub
		return getShiroBaseRealm().search(queryCriteria);
	}
	
	
	public List<ShiroAssociationRule> search(Collection<QueryMarker> queryCriteria) {
		// TODO Auto-generated method stub
		return getShiroBaseRealm().search(queryCriteria);
	}

	
	public final void checkPermissions(String...permissions)
			 throws NullPointerException, IllegalArgumentException, AccessException
	{
		checkPermissions(false, permissions);
	}
	
	
	public final void checkPermissions(boolean partial, String...permissions)
			 throws NullPointerException, IllegalArgumentException, AccessException
	{
		ShiroUtil.checkPermissions(partial, SecurityUtils.getSubject(), permissions);
	}

	@Override
	public final boolean hasPermission(String permission)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return ShiroUtil.isPermitted(permission);
	}


	@Override
	public final void checkRoles(String... roles) throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		checkRoles(false, roles);
	}
	
	public final void checkRoles(boolean partial, String... roles) throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		ShiroUtil.checkRoles(partial, SecurityUtils.getSubject(), roles);
	}

	/**
	 * Check the id the suer has the role
	 */
	@Override
	public final boolean hasRole(String role) throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return SecurityUtils.getSubject().hasRole(role);
	}


	@Override
	public void invalidateResource(String resourceID)
	{
		getShiroBaseRealm().invalidate(resourceID);
		
	}


	
	public void checkPermission(NVEntity nve, String permission)
			 throws NullPointerException, IllegalArgumentException, AccessException
	{
		if (!isPermitted(nve, permission))
		{
			throw new AccessException("Access Denied");
		}
	}
	
	
	public boolean isPermitted(NVEntity nve, String permission)
			 throws NullPointerException, IllegalArgumentException
	{
		SharedUtil.checkIfNulls("Null parameters", nve, nve.getReferenceID(), permission);
		boolean result = ShiroUtil.isPermitted(permission);
		if (result)
		{
			// the idea here is to match the permissions to the 
			// the nve and current subject
			ResourcePrincipalCollection nveRPC = new ResourcePrincipalCollection(nve);
			result = SecurityUtils.getSecurityManager().isPermitted(nveRPC, permission);
		}		
		return result;
	}
	
	
	public boolean isPermitted(String permissions)
			 throws NullPointerException, IllegalArgumentException
	{
		
		return  ShiroUtil.isPermitted(permissions);
	}


	@Override
	public String toString() {
		return "APISecurityManagerProvider{" +
				"daemon=" + daemon +
				'}';
	}
}
