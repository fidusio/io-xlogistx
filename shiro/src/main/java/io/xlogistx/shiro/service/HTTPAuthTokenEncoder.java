package io.xlogistx.shiro.service;

import io.xlogistx.shiro.authc.APIAuthenticationToken;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.zoxweb.shared.http.HTTPAuthorization;
import org.zoxweb.shared.util.DataEncoder;

public class HTTPAuthTokenEncoder
      implements DataEncoder<AuthenticationToken, HTTPAuthorization> {
    public static final HTTPAuthTokenEncoder SINGLETON = new HTTPAuthTokenEncoder();
    private HTTPAuthTokenEncoder() {}
    @Override
    public HTTPAuthorization encode(AuthenticationToken authToken) {

        if (authToken != null) {
            // convert AuthenticationToken to HTTPAuthorization

            if (authToken instanceof UsernamePasswordToken) {
                // we have a basic authentication
                return HTTPAuthorization.createBasic((String) authToken.getPrincipal(), new String((char[]) authToken.getCredentials()));
            } else if (authToken instanceof APIAuthenticationToken) {
                // TBD to change properly
               return HTTPAuthorization.createBearer(((APIAuthenticationToken) authToken).getToken());
            }

        }
        return null;
    }


}
