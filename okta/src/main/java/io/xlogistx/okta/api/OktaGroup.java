package io.xlogistx.okta.api;

import org.zoxweb.shared.util.NVGenericMap;

import java.util.Date;

public interface OktaGroup {


    enum GroupType
    {
        OKTA_GROUP,
        APP_GROUP,
        BUILT_IN,
    }

    public String getId();

    Date getCreationTime();
    Date getLastUpdate();
    Date getLastMembershipUpdate();
    GroupType getType();

    OktaGroupProfile getProfile();

    NVGenericMap getLinks();



}
