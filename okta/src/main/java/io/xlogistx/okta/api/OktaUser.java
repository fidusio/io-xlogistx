package io.xlogistx.okta.api;

import org.zoxweb.shared.util.NVGenericMap;

public interface OktaUser {

    public enum OktaUserStatus
    {
        STAGED,
        PROVISIONED,
        ACTIVE,
        RECOVERY,
        PASSWORD_EXPIRED,
        LOCKED_OUT,
        DEPROVISIONED
    }


    /**
     * OktaId for a registered user
     * @return
     */
    String getOktaId();

    OktaUserProfile getOktaProfile();
    OktaUser setOktaProfile(OktaUserProfile profile);

    OktaUser setOktaId(String id);
    OktaUserStatus getStatus();
    OktaUser setStatus(OktaUserStatus status);




    OktaCredentials getCredentials();
    OktaUser setCredentials(OktaCredentials credential);


    OktaUser addToGroupId(String id);



    NVGenericMap getLinks();

}
