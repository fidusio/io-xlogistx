package io.xlogistx.shiro.authz;

import io.xlogistx.shiro.ShiroBaseRealm;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.security.shiro.ShiroAssociationRule;
import org.zoxweb.shared.util.NVPair;
import org.zoxweb.shared.util.SUS;

import java.util.*;


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
		final ShiroAssociationRule sard;
		final NVPair[] tokens;
		RuleHolder(ShiroAssociationRule rule, NVPair[]  params)
		{
			this.sard = rule;
			this.tokens = (params != null && params.length > 0) ? params : null ;
		}
		
	}
	
	protected Map<String, RuleHolder> rulesMap = new LinkedHashMap<String, RuleHolder>();
	protected Set<ShiroAssociationRule> dynamicSet = new LinkedHashSet<ShiroAssociationRule>();
	protected Set<String> stringPermissions = null;
	protected Set<String> roles = null;
	protected Set<Permission> objectPermissions = null;
	private boolean dirty = true;
	private ShiroBaseRealm realm;
	public static final LogWrapper log = new LogWrapper(ShiroAuthorizationInfo.class);
	

	
	public ShiroAuthorizationInfo(ShiroBaseRealm realm)
	{
		this.realm = realm;
	}
	
	public synchronized void addShiroAssociationRule(ShiroAssociationRule sard, NVPair...nvps)
	{
		SUS.checkIfNulls("Null ShiroAssociationRule", sard);
		
		Date date = sard.getExpiration();
		
		if (date != null && date.getTime() < System.currentTimeMillis())
		{
			return;
		}
		
		rulesMap.put(sard.getReferenceID(), new RuleHolder(sard, nvps));
		dirty = true;
	}
	
	
	public synchronized void addDynamicShiroAssociationRule(ShiroAssociationRule sard)
	{
		SUS.checkIfNulls("Null ShiroAssociationRule", sard);
		
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
		throw new IllegalArgumentException("Not implemented");
//		 if(log.isEnabled()) log.getLogger().info("START:" + rulesMap.size());
//		if (dirty)
//		{
//			if (stringPermissions == null)
//			{
//				 stringPermissions = new LinkedHashSet<String>();
//			}
//			if (roles == null)
//			{
//				roles = new LinkedHashSet<String>();
//			}
//
//			if (objectPermissions == null)
//			{
//				objectPermissions = new LinkedHashSet<Permission>();
//			}
//			stringPermissions.clear();
//			roles.clear();
//			objectPermissions.clear();
//			Iterator<RuleHolder> it = rulesMap.values().iterator();
//			while(it.hasNext())
//			{
//				RuleHolder rh = it.next();
//				ShiroAssociationRule sard = rh.sard;
//				switch(sard.getAssociationType())
//				{
//				case PERMISSION_TO_ROLE:
//					break;
//				case PERMISSION_TO_RESOURCE:
//					break;
//				case PERMISSION_TO_SUBJECT:
//					if (sard.getAssociation() != null && sard.getAssociation() instanceof ShiroPermission)
//					{
//						ShiroPermission permission = sard.getAssociation();
//						if (permission.getPermissionPattern() != null)
//						{
//							stringPermissions.add(permission.getPermissionPattern());
//						}
//					}
//					else
//					{
//						stringPermissions.add(sard.getPattern());
//						// to avoid management permissions
//						if (sard.getAssociate() != null)
//						{
//							stringPermissions.add(SharedUtil.toCanonicalID(':', sard.getName(), CRUD.MOVE, sard.getAssociate()).toLowerCase());
//							try
//							{
//
//								Set<String> toAdds = realm.getRecursiveNVEReferenceIDFromForm(sard.getAssociate());
//								if (toAdds != null)
//								{
//									//System.out.println(toAdds);
//									for (String toAdd : toAdds)
//									{
//										stringPermissions.add(SharedUtil.toCanonicalID(':', sard.getName(), sard.getCRUD(), toAdd).toLowerCase());
//										// we will automatically grant MOVE permission if a permission exist
//										stringPermissions.add(SharedUtil.toCanonicalID(':', sard.getName(), CRUD.MOVE, toAdd).toLowerCase());
//									}
//								}
//							}
//							catch(Exception e)
//							{
//								e.printStackTrace();
//							}
//						}
//					}
//					break;
//				case ROLEGROUP_TO_SUBJECT:
//					break;
//				case ROLE_TO_ROLEGROUP:
//					break;
//				case ROLE_TO_SUBJECT:
//				case ROLE_TO_RESOURCE:
//					ShiroRole role = sard.getAssociation();
//					if (role != null)
//					{
//						//roles.add(role.getSubjectID());
//						for (NVEntity nve : role.getPermissions().values())
//						{
//							if (nve instanceof ShiroPermission)
//							{
//								ShiroPermission permission = (ShiroPermission) nve;
//								String permissionPattern = permission.getPermissionPattern();
//								if (permissionPattern != null)
//								{
//									// if(log.isEnabled()) log.getLogger().info("Original permission pattern:" + permissionPattern);
//									if (rh.tokens != null)
//									{
//										for (NVPair token: rh.tokens)
//										{
//											permissionPattern = PPEncoder.SINGLETON.encodePattern(permissionPattern, token);
//										}
//									}
//
//									if (permission.getDomainID() != null && permission.getDomainID() != null)
//										permissionPattern = PPEncoder.SINGLETON.encodePattern(permissionPattern, PermissionToken.APP_ID, AppIDDAO.appIDSubjectID(permission.getDomainID(), permission.getAppID()));
//									// if(log.isEnabled()) log.getLogger().info("Encoded permission pattern:" + permissionPattern);
//									stringPermissions.add(permissionPattern);
//								}
//							}
//						}
//					}
//
//					break;
//
//				}
//			}
//			dirty = false;
//		}
	}
	
	
	public synchronized void addShiroAssociationRule(Collection<ShiroAssociationRule> sards, NVPair ...nvps)
	{
		SUS.checkIfNulls("Null ShiroAssociationRule", sards);
		
		for(ShiroAssociationRule sard : sards)
		{
			addShiroAssociationRule(sard, nvps);
		}
	}
	
	
//	public synchronized void deleteShiroAssociationRule(ShiroAssociationRule sard)
//	{
//		
//	}
//	
//	public synchronized void updateShiroAssciationRule(ShiroAssociationRule sard)
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
