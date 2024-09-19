package io.xlogistx.shiro.service;

import io.xlogistx.shiro.DomainPrincipalCollection;
import io.xlogistx.shiro.authc.JWTAuthenticationToken;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.zoxweb.server.http.HTTPAPIEndPoint;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.CIPasswordHasher;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.crypto.CredentialHasher;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.http.HTTPAPIResult;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;
import org.zoxweb.shared.security.shiro.ShiroSessionData;
import org.zoxweb.shared.util.KVMapStore;
import org.zoxweb.shared.util.KVMapStoreDefault;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.SetNVProperties;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;

public class ShiroProxyRealm extends AuthorizingRealm
implements SetNVProperties
{

    public static final LogWrapper log = new LogWrapper(ShiroProxyRealm.class).setEnabled(false);

    private final KVMapStore<String, ShiroSessionData> kvSessionData = new KVMapStoreDefault<String, ShiroSessionData>(new HashMap<String, ShiroSessionData>());
    private final KVMapStore<String, AuthenticationInfo> kvAuthcInfo = new KVMapStoreDefault<String, AuthenticationInfo>(new HashMap<String, AuthenticationInfo>());

    private NVGenericMap configProperties;
    private CredentialHasher<CIPassword> credentialHasher = new CIPasswordHasher().setHashType(CryptoConst.HASHType.SHA_256).setIteration(64);



    private String configPath;
    private HTTPAPIEndPoint<AuthenticationToken, ShiroSessionData> remoteRealm;

    public ShiroProxyRealm()
    {
        super();
//        setName("ProxyRealm");
//        setAuthenticationCachingEnabled(true);
//        setAuthorizationCachingEnabled(true);


    }

    /**
     * This is a proxy realm meaning it depends on a remote server that actually
     * has the Subject info such as username or userid and the user credentials
     * The proxy realm will make a http call to the remote authentication server
     * The current system must be registered with remote server and authenticate the
     * request with a JWT token that Identifies the current system
     * the api call is a post call with a payload of the authentication token
     * the payload is a json object {"principal": token.getPrincipal(), "credentials": token.getCredentials()}
     * The remote server must validate the proxyrealm identity first
     * second validate the subject token, if the 2 validations passes return a json object that contains both
     * AuthenticationInfo and AuthorizationInfo
     * @param token the authentication token containing the user's principal and credentials.
     * @return the token AuthenticationInfo
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

        // This is a proxy realm it depends on a remote server that
        // has the Subject info such as username or userid and the user credentials
        // The proxy realm will make a http call to the remote authentication server
        // The current system must be registered with remote server and authenticate the
        // request with a JWT token that Identifies the current system
        // the api call is a post call with a payload of the authentication token
        // the payload is a json object {"principal": token.getPrincipal(), "credentials": token.getCredentials()}
        // The remote server must validate the re

        if(log.isEnabled()) log.getLogger().info("token: " + token) ;

        try
        {

            AuthenticationInfo authenticationInfo = kvAuthcInfo.get((String)token.getPrincipal());
            if(authenticationInfo != null)
                return authenticationInfo;

            if(remoteRealm != null)
            {
                HTTPAPIResult<ShiroSessionData> result = remoteRealm.syncCall(token);
                if (log.isEnabled()) log.getLogger().info("remoteRealm " + result);
                CIPassword passwordDAO = credentialHasher.hash((char[]) token.getCredentials());
                authenticationInfo = new SimpleAuthenticationInfo(token.getPrincipal(), passwordDAO, getName());

                kvSessionData.put((String) token.getPrincipal(), result.getData());
                kvAuthcInfo.put((String)token.getPrincipal(), authenticationInfo);

                return authenticationInfo;
            }
        }
        catch (Exception e)
        {
            if(log.isEnabled())
                e.printStackTrace();
        }

        throw new AuthenticationException("Invalid Authentication Token");
    }





    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals)
    {
        if(log.isEnabled()) log.getLogger().info(""+principals);
        String user = (String) principals.getPrimaryPrincipal();


        ShiroSessionData ssd = kvSessionData.get(user);
        SimpleAuthorizationInfo ret = new SimpleAuthorizationInfo();

        if(log.isEnabled()) log.getLogger().info(user +": " + ssd.permissions());
        if(log.isEnabled()) log.getLogger().info(user +": " + ssd.roles());
        ret.addStringPermissions(ssd.permissions());
        ret.addRoles(ssd.roles());

        return ret;


    }
    @Override
    public void setProperties(NVGenericMap properties) {
        this.configProperties = properties;
    }

    @Override
    public NVGenericMap getProperties() {
        return configProperties;
    }

    public void setRemoteRealm(HTTPAPIEndPoint<AuthenticationToken, ShiroSessionData> remoteRealm)
    {
        this.remoteRealm = remoteRealm;
    }



    protected Object getAuthenticationCacheKey(AuthenticationToken token)
    {
        if(log.isEnabled()) log.getLogger().info("TAG1::key:" + token);
        if(token instanceof JWTAuthenticationToken)
        {
            return ((JWTAuthenticationToken)token).getJWTSubjectID();
        }
        return super.getAuthenticationCacheKey(token);
    }

    protected Object getAuthenticationCacheKey(PrincipalCollection principals)
    {
        if(log.isEnabled()) log.getLogger().info("TAG2::key:" + principals);
        if (principals instanceof DomainPrincipalCollection)
        {
            DomainPrincipalCollection dpc = (DomainPrincipalCollection)principals;
            return dpc.getJWSubjectID() != null ? dpc.getJWSubjectID() : dpc.getPrimaryPrincipal();
        }
        return super.getAuthenticationCacheKey(principals);
    }



    public String getConfigPath() {
        return configPath;
    }

    public void setConfigPath(String configPath) throws IOException
    {
        try {
            if (log.isEnabled()) log.getLogger().info(configPath);
            this.configPath = configPath;
            // load configProperties
            File resoureFile = IOUtil.locateFile(configPath);
            if (log.isEnabled()) log.getLogger().info("File: " + resoureFile);

            configProperties = GSONUtil.fromJSONDefault(IOUtil.inputStreamToString(resoureFile), NVGenericMap.class);
            if (log.isEnabled()) log.getLogger().info("json loaded " + configProperties);


            NVGenericMap proxyRealmAPIConfig = (NVGenericMap) configProperties.get("shiro-proxy-http-api");
            String domain = proxyRealmAPIConfig.getValue("domain");
            HTTPMessageConfigInterface hmciConfig = proxyRealmAPIConfig.getValue("hmci-config");
            ShiroProxyHTTPAPI httpapi = new ShiroProxyHTTPAPI(hmciConfig);
            httpapi.setDomain(domain).setName(hmciConfig.getName());
            setRemoteRealm(httpapi);

            NVGenericMap passwordHashConfig = (NVGenericMap) proxyRealmAPIConfig.get("credential-hasher");
            if (log.isEnabled()) log.getLogger().info("credential-hasher: " + passwordHashConfig);
            if (passwordHashConfig != null) {
                try {
                    CIPasswordHasher passwordHasher = new CIPasswordHasher();
                    passwordHasher.setHashType(CryptoConst.HASHType.lookup(passwordHashConfig.getValue("hash_type")))
                            .setIteration(passwordHashConfig.getValue("iteration"));
                    credentialHasher = passwordHasher;
                    if (log.isEnabled())
                        log.getLogger().info("Credential hasher: " + passwordHasher.getHashType() + " " + passwordHasher.getIteration());
                } catch (Exception e) {
                    e.printStackTrace();
                }

            }


            if (log.isEnabled()) log.getLogger().info("remote realm set");
        }
        catch (Exception e)
        {
            e.printStackTrace();
            throw new IOException(e.getMessage());
        }
    }
}
