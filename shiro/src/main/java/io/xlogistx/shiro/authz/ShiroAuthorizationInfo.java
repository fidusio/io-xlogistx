package io.xlogistx.shiro.authz;

import io.xlogistx.shiro.ShiroBaseRealm;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.zoxweb.shared.data.AppIDDAO;
import org.zoxweb.shared.security.model.PPEncoder;
import org.zoxweb.shared.security.model.SecurityModel.PermissionToken;
import org.zoxweb.shared.security.shiro.ShiroAssociationRuleDAO;
import org.zoxweb.shared.security.shiro.ShiroPermissionDAO;
import org.zoxweb.shared.security.shiro.ShiroRoleDAO;
import org.zoxweb.shared.util.CRUD;
import org.zoxweb.shared.util.NVEntity;
import org.zoxweb.shared.util.NVPair;
import org.zoxweb.shared.util.SharedUtil;

import java.util.*;
import java.util.logging.Logger;


/**
 * Fidus Store implementation of shiro AuthorizationInfo
 * @author mnael
 *
 */
@SuppressWarnings("serial")
public class ShiroAuthorizationInfo implements AuthorizationInfo
{
	
	static class RuleHolder
	{
		final ShiroAssociationRuleDAO sard;
		final NVPair[] tokens;
		RuleHolder(ShiroAssociationRuleDAO rule, NVPair[]  params)
		{
			this.sard = rule;
			this.tokens = (params != null && params.length > 0) ? params : null ;
		}
		
	}
	
	protected Map<String, RuleHolder> rulesMap = new LinkedHashMap<String, RuleHolder>();
	protected Set<ShiroAssociationRuleDAO> dynamicSet = new LinkedHashSet<ShiroAssociationRuleDAO>();
	protected Set<String> stringPermissions = null;
	protected Set<String> roles = null;
	protected Set<Permission> objectPermissions = null;
	private boolean dirty = true;
	private ShiroBaseRealm realm;
	private static final transient Logger log = Logger.getLogger(ShiroAuthorizationInfo.class.getName());
	
	
	
//	public static String getNVEReferenceIDFromForm(FidusStoreShiroRealm realm, String formReferenceID)
//	{
//		MongoDataStore mds = (MongoDataStore) realm.getDataStore();
//		BasicDBObject projection = new BasicDBObject();
//		projection = projection.append(FormInfoDAO.Params.FORM_REFERENCE.getNVConfig().getName(), true);
//		BasicDBObject result = mds.lookupByReferenceID(FormInfoDAO.NVC_FORM_INFO_DAO.getName(), new ObjectId(formReferenceID), projection);
//		if (result != null)
//		{
//			BasicDBObject form_reference = (BasicDBObject) result.get(FormInfoDAO.Params.FORM_REFERENCE.getNVConfig().getName());
//			if (form_reference != null)
//			{
//				ObjectId nveReferenceID = (ObjectId) form_reference.get(FormInfoDAO.NVC_REFERENCE_ID.getName());
//				if (nveReferenceID != null)
//				{
//					return nveReferenceID.toHexString();
//				}
//			}
//		}
//		
//		return null;
//	}
	
	

	
	
	
	
	
	
	
	public ShiroAuthorizationInfo(ShiroBaseRealm realm)
	{
		this.realm = realm;
	}
	
	public synchronized void addShiroAssociationRule(ShiroAssociationRuleDAO sard, NVPair...nvps)
	{
		SharedUtil.checkIfNulls("Null ShiroAssociationRuleDAO", sard);
		
		Date date = sard.getExpiration();
		
		if (date != null && date.getTime() < System.currentTimeMillis())
		{
			return;
		}
		
		rulesMap.put(sard.getReferenceID(), new RuleHolder(sard, nvps));
		dirty = true;
	}
	
	
	public synchronized void addDynamicShiroAssociationRule(ShiroAssociationRuleDAO sard)
	{
		SharedUtil.checkIfNulls("Null ShiroAssociationRuleDAO", sard);
		
		Date date = sard.getExpiration();
		
		if (date != null && date.getTime() < System.currentTimeMillis())
		{
			return;
		}
		
		rulesMap.put(sard.getPattern(), new RuleHolder(sard, null));
		dirty = true;
	}
	
	private synchronized void update()
	{
		log.info("START:" + rulesMap.size());
		if (dirty)
		{
			if (stringPermissions == null)
			{
				 stringPermissions = new LinkedHashSet<String>();
			}
			if (roles == null)
			{
				roles = new LinkedHashSet<String>();
			}
			
			if (objectPermissions == null)
			{
				objectPermissions = new LinkedHashSet<Permission>();
			}
			stringPermissions.clear();
			roles.clear();
			objectPermissions.clear();
			Iterator<RuleHolder> it = rulesMap.values().iterator();
			while(it.hasNext())
			{
				RuleHolder rh = it.next();
				ShiroAssociationRuleDAO sard = rh.sard;
				switch(sard.getAssociationType())
				{
				case PERMISSION_TO_ROLE:
					break;
				case PERMISSION_TO_RESOURCE:
					break;
				case PERMISSION_TO_SUBJECT:
					if (sard.getAssociation() != null && sard.getAssociation() instanceof ShiroPermissionDAO)
					{
						ShiroPermissionDAO permission = sard.getAssociation();
						if (permission.getPermissionPattern() != null)
						{
							stringPermissions.add(permission.getPermissionPattern());
						}
					}
					else
					{
						stringPermissions.add(sard.getPattern());
						// to avoid management permissions
						if (sard.getAssociate() != null)
						{
							stringPermissions.add(SharedUtil.toCanonicalID(':', sard.getName(), CRUD.MOVE, sard.getAssociate()).toLowerCase());
							try
							{						
										
								Set<String> toAdds = realm.getRecusiveNVEReferenceIDFromForm(sard.getAssociate());
								if (toAdds != null)
								{
									//System.out.println(toAdds);
									for (String toAdd : toAdds)
									{
										stringPermissions.add(SharedUtil.toCanonicalID(':', sard.getName(), sard.getCRUD(), toAdd).toLowerCase());
										// we will automatically grant MOVE permission if a permission exist
										stringPermissions.add(SharedUtil.toCanonicalID(':', sard.getName(), CRUD.MOVE, toAdd).toLowerCase());
									}
								}
							}
							catch(Exception e)
							{
								e.printStackTrace();
							}
						}
					}
					break;
				case ROLEGROUP_TO_SUBJECT:
					break;
				case ROLE_TO_ROLEGROUP:
					break;
				case ROLE_TO_SUBJECT:
				case ROLE_TO_RESOURCE:
					ShiroRoleDAO role = sard.getAssociation();
					if (role != null)
					{
						roles.add(role.getSubjectID());
						for (NVEntity nve : role.getPermissions().values())
						{
							if (nve instanceof ShiroPermissionDAO)
							{
								ShiroPermissionDAO permission = (ShiroPermissionDAO) nve;
								String permissionPattern = permission.getPermissionPattern();
								if (permissionPattern != null)
								{
									//log.info("Original permission pattern:" + permissionPattern);
									if (rh.tokens != null)
									{
										for (NVPair token: rh.tokens)
										{
											permissionPattern = PPEncoder.SINGLETON.encodePattern(permissionPattern, token);
										}
									}
									
									if (permission.getDomainID() != null && permission.getDomainID() != null)
										permissionPattern = PPEncoder.SINGLETON.encodePattern(permissionPattern, PermissionToken.APP_ID, AppIDDAO.appIDSubjectID(permission.getDomainID(), permission.getAppID()));
									//log.info("Encoded permission pattern:" + permissionPattern);
									stringPermissions.add(permissionPattern);
								}
							}
						}
					}
					
					break;

				}
			}
			dirty = false;
		}
	}
	
	
	public synchronized void addShiroAssociationRule(Collection<ShiroAssociationRuleDAO> sards, NVPair ...nvps)
	{
		SharedUtil.checkIfNulls("Null ShiroAssociationRuleDAO", sards);
		
		for(ShiroAssociationRuleDAO sard : sards)
		{
			addShiroAssociationRule(sard, nvps);
		}
	}
	
	
//	public synchronized void deleteShiroAssociationRule(ShiroAssociationRuleDAO sard)
//	{
//		
//	}
//	
//	public synchronized void updateShiroAssciationRule(ShiroAssociationRuleDAO sard)
//	{
//		
//	}

	@Override
	public synchronized Collection<String> getRoles()
	{
		if (dirty)
		{
			update();
		}
		
		return roles;
	}

	@Override
	public synchronized Collection<String> getStringPermissions()
	{
		if (dirty)
		{
			update();
		}
		
		return stringPermissions;
	}

	@Override
	public synchronized Collection<Permission> getObjectPermissions()
	{
		if (dirty)
		{
			update();
		}
		
		return objectPermissions;
	}

}
