package io.xlogistx.okta.api;

import com.google.gson.annotations.SerializedName;

public class DefaultOktaUserProfile
implements OktaUserProfile
{
    private String firstName;
    private String lastName;

    private String email;
    @SerializedName("login")
    private String userName;
    private String mobilePhone;

    private String uuid;

    @Override
    public String getUserName() {
        return userName;
    }

    @Override
    public OktaUserProfile setUserName(String username) {
        this.userName = username;
        return this;
    }

    @Override
    public String getEmail() {
        return email;
    }

    @Override
    public OktaUserProfile setEmail(String email) {
        this.email = email;
        return this;
    }



    @Override
    public String getFirstName() {
        return firstName;
    }

    @Override
    public OktaUserProfile setFirstName(String name) {
        this.firstName = name;
        return this;
    }

    @Override
    public String getLastName() {
        return lastName;
    }

    @Override
    public OktaUserProfile setLastName(String lastName) {
        this.lastName = lastName;
        return this;
    }

    @Override
    public String getMobilePhone() {
        return mobilePhone ;
    }

    @Override
    public OktaUserProfile setMobilePhone(String phone) {
        this.mobilePhone = phone;
        return this;
    }

    @Override
    public String getUUID() {
        return uuid;
    }

    @Override
    public OktaUserProfile setUUID(String uuid) {
        this.uuid = uuid;
        return this;
    }

    @Override
    public String toString() {
        return "DefaultOktaProfile{" +
                "firstName='" + firstName + '\'' +
                ", lastName='" + lastName + '\'' +
                ", email='" + email + '\'' +
                ", userName='" + userName + '\'' +
                ", mobilePhone='" + mobilePhone + '\'' +
                ", uuid='" + uuid + '\'' +
                '}';
    }
}
