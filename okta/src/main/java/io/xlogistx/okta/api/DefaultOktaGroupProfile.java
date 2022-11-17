package io.xlogistx.okta.api;

public class DefaultOktaGroupProfile
implements OktaGroupProfile
{
    private String name;
    private String description;

    @Override
    public String getDescription() {
        return description;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return "DefaultOktaGroupProfile{" +
                "name='" + name + '\'' +
                ", description='" + description + '\'' +
                '}';
    }
}
