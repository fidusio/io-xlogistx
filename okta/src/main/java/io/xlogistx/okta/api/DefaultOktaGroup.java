package io.xlogistx.okta.api;

import com.google.gson.annotations.SerializedName;
import org.zoxweb.shared.util.NVGenericMap;

import java.util.Date;

public class DefaultOktaGroup
    implements OktaGroup
{
    private String id;
    private Date created;
    private Date lastUpdated;
    private Date lastMembershipUpdated;
    private GroupType type;

    @SerializedName("_links")
    private NVGenericMap links;

    private DefaultOktaGroupProfile profile;

    @Override
    public String getId() {
        return id;
    }

    @Override
    public Date getCreationTime() {
        return created;
    }

    @Override
    public Date getLastUpdate() {
        return lastUpdated;
    }

    @Override
    public Date getLastMembershipUpdate() {
        return lastMembershipUpdated;
    }

    @Override
    public GroupType getType() {
        return type;
    }

    @Override
    public OktaGroupProfile getProfile() {
        return profile;
    }

    @Override
    public NVGenericMap getLinks() {
        return links;
    }


    @Override
    public String toString() {
        return "DefaultOktaGroup{" +
                "id='" + id + '\'' +
                ", created=" + created +
                ", lastUpdated=" + lastUpdated +
                ", lastMembershipUpdated=" + lastMembershipUpdated +
                ", type=" + type +
                ", links=" + links +
                ", profile=" + profile +
                '}';
    }
}
