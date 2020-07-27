package io.xlogistx.shiro;

import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;

import java.util.HashMap;
import java.util.Map;
//import org.zoxweb.server.security.shiro.authz.PermissionsProp;

public class ShiroResourcePropContainer
	extends ShiroResourceProp<Class<?>>
{

	private Map<Object, ShiroResourceProp<?>> mapByResource = new HashMap<Object, ShiroResourceProp<?>>();
	private Map<Object, ShiroResourceProp<?>> mapByResourceMap = new HashMap<Object, ShiroResourceProp<?>>();
	
	public ShiroResourcePropContainer(Class<?> resource, boolean authc, RequiresRoles roles, RequiresPermissions permissions)
	{
		super(resource, authc, roles, permissions, null, null);
		// TODO Auto-generated constructor stub
	}
	
	public void add(ShiroResourceProp<?> srp)
	{
		if (srp != null)
			mapByResource.put(srp.resource, srp);
	}
	
	public void map(Object resourceMap, ShiroResourceProp<?> srp)
	{
		mapByResourceMap.put(resourceMap, srp);
	}
	
	public ShiroResourceProp<?> lookupByResource(Object res)
	{
		return mapByResource.get(res);
	}
	
	public ShiroResourceProp<?> lookupByResourceMap(Object res)
	{
		return mapByResourceMap.get(res);
	}
	
	public ShiroResourceProp<?>[] getAllResources()
	{
		return mapByResource.values().toArray(new ShiroResourceProp[0]);
	}
	

}
