package io.xlogistx.shiro;

import io.xlogistx.shiro.authz.ManualAuthorizationCheck;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;

import org.zoxweb.shared.annotation.DataProp;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;



public class ShiroResourcePropScanner
{
	private ShiroResourcePropScanner()
	{	
	}
	
	public static ShiroResourcePropContainer scan(Class<?> clazz)
	{
		ShiroResourcePropContainer ret = null;
		{
			boolean  authc = false;
			RequiresPermissions permissionAnnot = null;
			RequiresRoles rolesAnnot = null;
			
			for (Annotation a : clazz.getAnnotations())
			{
				
				if (a.annotationType() == RequiresAuthentication.class)
				{
					authc = true;
					
				}
				else if (a.annotationType() == RequiresPermissions.class)
				{
					permissionAnnot = (RequiresPermissions) a;
				}
				else if (a.annotationType() == RequiresRoles.class)
				{
					rolesAnnot = (RequiresRoles) a;
				}	
			}
			
			ret = new ShiroResourcePropContainer(clazz, authc, rolesAnnot, permissionAnnot);
		}
		
		for(Method m : clazz.getMethods())
		{
			ShiroResourceProp<Method> srp = null;
			
			boolean  authc = false;
			RequiresPermissions permissionAnnot = null;
			RequiresRoles rolesAnnot = null;
			ManualAuthorizationCheck permissionsProp = null;
			DataProp dataProp = null;
			
			
			for (Annotation a : m.getAnnotations())
			{
				
				if (a.annotationType() == RequiresAuthentication.class)
				{
					authc = true;
				}
				else if (a.annotationType() == RequiresPermissions.class)
				{
					permissionAnnot = (RequiresPermissions) a;
				}
				else if (a.annotationType() == RequiresRoles.class)
				{
					rolesAnnot = (RequiresRoles) a;
				}
				else if (a.annotationType() == ManualAuthorizationCheck.class)
				{
					permissionsProp = (ManualAuthorizationCheck) a;
				}
				else if (a.annotationType() == DataProp.class)
				{
					dataProp = (DataProp) a;
				}
			}
			
			if (authc || permissionAnnot != null || rolesAnnot != null || dataProp != null)
				srp = new ShiroResourceProp<Method>(m, authc, rolesAnnot, permissionAnnot, permissionsProp, dataProp);
			
			ret.add(srp);
		}
		
		
		
		return ret;
	}
}
