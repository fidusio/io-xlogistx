package io.xlogistx.shiro;


import io.xlogistx.shiro.authz.ManualAuthorizationCheck;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;

import org.zoxweb.shared.annotation.DataProp;



public class ShiroResourceProp<T>
{
	public final T resource;
	
	public final boolean isAuthcRequired;
	public final RequiresRoles roles;
	public final RequiresPermissions permissions;
	public final ManualAuthorizationCheck manualAuthorizationCheck;
	public final DataProp dataProperties;
	
	
	public ShiroResourceProp(T resource, boolean authc, RequiresRoles roles, RequiresPermissions permissions, ManualAuthorizationCheck mac, DataProp dp)
	{
		this.resource = resource;
		this.isAuthcRequired = authc;
		this.roles = roles;
		this.permissions = permissions;
		this.dataProperties = dp; 
		this.manualAuthorizationCheck = mac;
	}
	
	

}
