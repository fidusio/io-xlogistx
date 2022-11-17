package io.xlogistx.okta.api;


import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.http.HTTPAuthentication;
import org.zoxweb.shared.util.GetNameValue;
import org.zoxweb.shared.util.GetValue;
import org.zoxweb.shared.util.NVGenericMap;

import java.io.IOException;

public interface OktaAdapter
{
    public static final LogWrapper log = new LogWrapper(OktaAdapter.class).setEnabled(false);
    public static final String URI_PREFIX = "/api/v1/";


    public enum Token
        implements GetValue<String>
    {
        USERID("${userId}"),
        ;
        private final String value;
        Token(String val)
        {
            value = val;
        }
        @Override
        public String getValue() {
            return value;
        }
    }
    public enum URIs
        implements GetValue<String>
    {
        AUTHN("authn"),
        USERS("users"),
        USER_CHANGE_PASSWORD("users/" +Token.USERID.getValue() + "/credentials/change_password"),
        USER_DEACTIVATE("users/" +Token.USERID.getValue() + "/lifecycle/deactivate"),
        USER_DELETE("users/" +Token.USERID.getValue()),
        GROUPS("groups"),
        ;

        URIs(String val)
        {
            value = URI_PREFIX + val;
        }

        private final String value;
        @Override
        public String getValue() {
            return value;
        }
    }
//    Client getClient();
//    OktaAdapter setClient(Client client);

    /**
     * Get the okta application URL
     * @return the url
     */
    String getURL();

    /**
     * Set the okta application url
     * @param url
     * @return self
     */
    OktaAdapter setURL(String url);

    /**
     * Get the authentication token
     * @return app auth token
     */
    HTTPAuthentication getHTTPAuthentication();

    /**
     * Set the authentication token
     * @param httpAuthentication to be set
     * @return self
     */
    OktaAdapter setHTTPAuthentication(HTTPAuthentication httpAuthentication);


    /**
     * Register a user if the UUID of the user is null it will be automatically generated
     * This method requires admin privilege
     * @param user to be registered with okta
     * @return the oktified user with the oktaId set
     * @throws IOException in case of and error
     */
    OktaUser registerUser(OktaUser user, boolean activate, String ...groups) throws IOException;

    /**
     * Look a user based on his userName/login or oktaId
     * @param oktaIdOrUserID
     * @return the user info
     * @throws IOException
     */
    OktaUser lookupUser(String oktaIdOrUserID) throws IOException;

    OktaAdapter deleteUser(String username) throws IOException;
    OktaAdapter deleteUser(OktaUser oktaUser) throws IOException;
    OktaUser[] listGroupUsers(String group) throws IOException;


    OktaUser lookupByUUID(String username);
    OktaAdapter deleteByUUID(String uuid);


    NVGenericMap userLogin(String userName, String password) throws IOException;
    OktaUser userUpdatePassword(String oktaIdUserName, String oldPassword, String newPassword) throws IOException;

    OktaUser updatePassword(String oktaIdUserName, String password) throws IOException;
    OktaUser updateOktaUser(OktaUser oktaUser) throws IOException;

    boolean isHttpCallingEnabled();
    OktaAdapter enableHttpCalling(boolean stat);

    OktaUser[] listUsers(GetNameValue<String>...queries) throws IOException;


    OktaGroup[] listGroups() throws IOException;

    OktaAPIRate getCurrentAPIRate();

}
