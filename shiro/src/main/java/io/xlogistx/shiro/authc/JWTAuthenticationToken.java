package io.xlogistx.shiro.authc;

import org.apache.shiro.authc.HostAuthenticationToken;
import org.apache.shiro.authc.RememberMeAuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.zoxweb.shared.security.JWTToken;
import org.zoxweb.shared.util.AppID;
import org.zoxweb.shared.util.SharedUtil;

@SuppressWarnings("serial")
public class JWTAuthenticationToken
extends UsernamePasswordToken
implements AppID<String>, HostAuthenticationToken, RememberMeAuthenticationToken
{
	
	private JWTToken jwtToken;
	private boolean rememberMe = false;
	private String host;
	private String subjectID;
	
	public JWTAuthenticationToken()
	{
		
	}
	
	
	
	public JWTAuthenticationToken(JWTToken jwtToken)
	{
		this(jwtToken, null, false);
	}
	
	public JWTAuthenticationToken(JWTToken jwtToken, String host)
	{
		this(jwtToken, host, false);
	}
	
	public JWTAuthenticationToken(JWTToken jwtToken, String host, boolean rememberMe)
	{
		SharedUtil.checkIfNulls("JWTToken can not be null", jwtToken, jwtToken.getJWT(), jwtToken.getToken(), jwtToken.getJWT().getPayload(), jwtToken.getJWT().getPayload().getSubjectID());
		this.jwtToken = jwtToken;
		this.host = host;
		this.rememberMe = rememberMe;
	}
	

	@Override
	public String getDomainID() {
		// TODO Auto-generated method stub
		return jwtToken.getJWT().getPayload().getDomainID();
	}

	@Override
	public void setDomainID(String domainID) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public String getSubjectID() {
		// TODO Auto-generated method stub
		return subjectID;
	}
	
	
	public String getJWTSubjectID()
	{
		return jwtToken.getJWT().getPayload().getSubjectID();
	}

	@Override
	public void setSubjectID(String id) {
		// TODO Auto-generated method stub
		this.subjectID = id;
	}


	@Override
	public Object getPrincipal() {
		// TODO Auto-generated method stub
		return getSubjectID();
	}

	@Override
	public Object getCredentials() {
		// TODO Auto-generated method stub
		return jwtToken.getToken();
	}

	@Override
	public boolean isRememberMe() {
		// TODO Auto-generated method stub
		return rememberMe;
	}

	@Override
	public String getHost() {
		// TODO Auto-generated method stub
		return host;
	}

	@Override
	public String getAppID() {
		// TODO Auto-generated method stub
		return jwtToken.getJWT().getPayload().getAppID();
	}

	@Override
	public void setAppID(String appID) {
		// TODO Auto-generated method stub
		
	}

}
