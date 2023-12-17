package io.xlogistx.shiro.service;

import io.xlogistx.shiro.authc.APIAuthenticationToken;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.zoxweb.server.http.HTTPAPIEncoder;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.http.HTTPAuthorization;
import org.zoxweb.shared.http.HTTPAuthorizationBasic;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;

public class AuthenticationTokenEncoder
    extends HTTPAPIEncoder<AuthenticationToken>
{
    @Override
    public HTTPMessageConfigInterface encode(HTTPMessageConfigInterface hmci, AuthenticationToken authToken)
    {
        HTTPAuthorization auth = hmci.getAuthorization();
        if (auth == null)
        {
            // convert AuthenticationToken to HTTPAuthorization

            if (authToken instanceof UsernamePasswordToken)
            {
                // we have a basic authentication
                auth = new HTTPAuthorizationBasic((String) authToken.getPrincipal(), new String((char[])authToken.getCredentials()));
            }
            else if (authToken instanceof APIAuthenticationToken)
            {
                auth = new HTTPAuthorization(((APIAuthenticationToken) authToken).getType(),((APIAuthenticationToken) authToken).getToken());
            }
            hmci.setAuthorization(auth);
        }
        else
        {
            // convert AuthenticationToken to HTTPAuthorization in post mode
            switch(hmci.getMethod())
            {
                case POST:
                case PUT:
                case PATCH:
                    // create NVGM object
                    hmci.setContent(GSONUtil.toJSONDefault(authToken));
                break;
            }
        }
        return hmci;
    }
}
