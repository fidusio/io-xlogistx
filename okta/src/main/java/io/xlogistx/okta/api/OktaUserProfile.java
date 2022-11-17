package io.xlogistx.okta.api;

public interface OktaUserProfile {

    /**
     * The user login
     * @return
     */
    String getUserName();

    /**
     * The login user for okta
     * @param username usually an email
     */
    OktaUserProfile setUserName(String username);



    /**
     * The user email address
     * @return
     */
    String getEmail();

    /**
     *
     * @param email of the user
     */
    OktaUserProfile setEmail(String email);

    String getFirstName();
    OktaUserProfile setFirstName(String name);
    String getLastName();
    OktaUserProfile setLastName(String name);

    String getMobilePhone();
    OktaUserProfile setMobilePhone(String phone);

    String getUUID();
    OktaUserProfile setUUID(String uuid);

}
