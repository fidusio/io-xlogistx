package io.xlogistx.shiro.authc;

import org.apache.shiro.authc.HostAuthenticationToken;
import org.zoxweb.shared.util.SubjectID;

public class APIAuthenticationToken
implements HostAuthenticationToken, SubjectID<String>
{
    private final String token;
    private final String type;
    private String subjectID;


    public APIAuthenticationToken(String type, String token)
    {
        this.type = type;
        this.token = token;
    }
    public APIAuthenticationToken(String subjectID, String type, String token)
    {
        this.subjectID = subjectID;
        this.type = type;
        this.token = token;
    }


    @Override
    public String getHost() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return getSubjectID();
    }

    @Override
    public Object getCredentials() {
        return getToken();
    }

    public String getType()
    {
        return type;
    }

    public String getToken()
    {
        return token;
    }

    @Override
    public void setSubjectID(String id) {
        subjectID = id;
    }

    @Override
    public String getSubjectID() {
        return subjectID;
    }
}
