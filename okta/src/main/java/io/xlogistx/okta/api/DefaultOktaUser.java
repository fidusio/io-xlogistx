package io.xlogistx.okta.api;

import com.google.gson.annotations.SerializedName;
import org.zoxweb.shared.util.NVGenericMap;

import java.util.HashSet;
import java.util.Set;


public class DefaultOktaUser
implements OktaUser
{

    private String id = null;
    private DefaultOktaUserProfile profile = null;
    private OktaCredentials credentials = null ;
    @SerializedName("_links")
    private NVGenericMap links = null;

    private Set<String> groupIds = null;



    private OktaUserStatus status = null;


    public DefaultOktaUser()
    {

    }

//    public DefaultOktaUser(User user)
//    {
//        setOktaId(user.getId());
//        setOktaProfile(new DefaultOktaProfile());
//        getOktaProfile()
//        .setFirstName(user.getProfile().getFirstName())
//        .setLastName(user.getProfile().getLastName())
//        .setEmail(user.getProfile().getEmail())
//        .setMobilePhone(user.getProfile().getMobilePhone());
//
//        setUUID(user.getProfile().getString("uuid"));
//
//    }



    @Override
    public synchronized String getOktaId() {
        return id;
    }
    @Override
    public synchronized OktaUser setOktaId(String id) {
        this.id = id;
        return this;
    }

    @Override
    public OktaUserProfile getOktaProfile() {
        return profile;
    }

    @Override
    public OktaUser setOktaProfile(OktaUserProfile profile) {
        this.profile = (DefaultOktaUserProfile) profile;
        return this;
    }

    @Override
    public OktaUserStatus getStatus()
    {
        return status;
    }

    @Override
    public OktaUser setStatus(OktaUserStatus status) {
        return this;
    }

    @Override
    public NVGenericMap getLinks()
    {
        return links;
    }






    @Override
    public OktaCredentials getCredentials() {
        return credentials;
    }

    @Override
    public OktaUser setCredentials(OktaCredentials credential) {
        this.credentials =  credential;
        return this;
    }

    @Override
    public OktaUser addToGroupId(String groupId) {
        if (groupIds == null)
        {
            synchronized (this)
            {
                if (groupIds == null)
                    groupIds = new HashSet<>();
            }
        }
        groupIds.add(groupId);

        return this;
    }


    @Override
    public String toString() {
        return "DefaultOktaUser{" +
                "oktaId='" + id + '\'' +
                ", profile=" + profile +
                ", credentials=" + credentials +
                ", links=" + links +
                ", status=" + status +
                '}';
    }
}
