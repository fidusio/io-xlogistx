package io.xlogistx.shiro;

import org.apache.shiro.subject.SimplePrincipalCollection;
import org.zoxweb.shared.util.NVEntity;

public class ResourcePrincipalCollection 
	extends SimplePrincipalCollection
{
	/**
	 * 
	 */
	private static final long serialVersionUID = 3358513294780981121L;

	
	
	public ResourcePrincipalCollection(NVEntity nve)
	{
		this(nve.getReferenceID());
	}
	
	public ResourcePrincipalCollection(String principal)
	{
		super(principal, ShiroUtil.getRealm(ShiroBaseRealm.class).getName());
	}
	
	public ResourcePrincipalCollection(String principal, String realmName)
	{
		super(principal, realmName);
	}
}
