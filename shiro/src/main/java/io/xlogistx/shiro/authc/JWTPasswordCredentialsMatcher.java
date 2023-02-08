package io.xlogistx.shiro.authc;

import io.xlogistx.shiro.DomainPrincipalCollection;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.security.JWTProvider;
import org.zoxweb.shared.crypto.PasswordDAO;
import org.zoxweb.shared.security.JWT;
import org.zoxweb.shared.security.SubjectAPIKey;
import org.zoxweb.shared.util.Const.Status;
import org.zoxweb.shared.util.SharedStringUtil;

public class JWTPasswordCredentialsMatcher implements CredentialsMatcher {
	public static final LogWrapper log = new LogWrapper(JWTPasswordCredentialsMatcher.class).setEnabled(false);
	@Override
	public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info)
	{
		
		
		try
        {
		
			if (info.getCredentials() instanceof PasswordDAO)
			{
				if (!token.getPrincipal().equals(info.getPrincipals().getPrimaryPrincipal()))
				{
					return false;
				}
			
				if (token instanceof DomainUsernamePasswordToken
	                    && ((DomainUsernamePasswordToken)token).isAutoAuthenticationEnabled())
				{
					return true;
				}
				
				//if(log.isEnabled()) log.getLogger().info("SimpleAuthentication token:" + token.getClass().getName());
			
	
				PasswordDAO passwordDAO = (PasswordDAO) info.getCredentials();
				String password = null;
				
				if (token.getCredentials() instanceof char[])
				{
					password = new String((char[])token.getCredentials());
				}
				else if (token.getCredentials() instanceof byte[])
				{
					password = SharedStringUtil.toString((byte[])token.getCredentials());
				}
				else if(token.getCredentials() instanceof String)
				{
					password = (String) token.getCredentials();
				}
				
				return CryptoUtil.isPasswordValid(passwordDAO, password);
			}
			else if (info.getCredentials() instanceof SubjectAPIKey && token instanceof JWTAuthenticationToken)
			{
				//if(log.isEnabled()) log.getLogger().info("JWTAuthenticationToken");
				SubjectAPIKey sak = (SubjectAPIKey) info.getCredentials();
				if (sak.getStatus() != Status.ACTIVE)
				{
					// not active anymore
					return false;
				}
				if (sak.getExpiryDate() != 0)
				{
					if (System.currentTimeMillis() > sak.getExpiryDate())
					{
						return false;
					}
				}
				JWT jwt = JWTProvider.SINGLETON.decode(sak.getAPIKeyAsBytes(), (String)token.getCredentials());
				if (info instanceof DomainAuthenticationInfo)
				{
					DomainAuthenticationInfo dai = (DomainAuthenticationInfo) info;
					DomainPrincipalCollection dpc =	(DomainPrincipalCollection) dai.getPrincipals();
					// if the token is not matching the domain id and app id we have a problem 
					if ( !(dpc.getDomainID().equalsIgnoreCase(jwt.getPayload().getDomainID()) && 
						 dpc.getAppID().equalsIgnoreCase(jwt.getPayload().getAppID())))
					{
						return false;
					}
				}
				return true;
			}
		}
		catch (Exception e)
        {
			e.printStackTrace();
		}
		
		return false;
	}

}
