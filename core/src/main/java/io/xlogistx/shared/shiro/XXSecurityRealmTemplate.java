package io.xlogistx.shared.shiro;

import org.zoxweb.shared.util.GetName;
import org.zoxweb.shared.util.GetNameValue;
import org.zoxweb.shared.util.GetValue;

public class XXSecurityRealmTemplate {

  public enum PTag
      implements GetNameValue<String> {

    SELF("self", "$$self$$"),
    APP_ID("app_id", "$$app_id$$"),
    ALL("all", "*"),
    COLON("colon", ":"),

    ;

    private final String value;
    private final String name;

    PTag(String name, String value) {
      this.name = name;
      this.value = value;
    }

    @Override
    public String getName() {
      return name;
    }

    @Override
    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return value;
    }

  }

  public enum ActionTag
      implements GetValue<String> {

    CREATE("create"),
    READ("read"),
    UPDATE("update"),
    DELETE("delete"),
    ACCESS("access"),
    LOOKUP("lookup"),
    ASSIGN("assign");

    private final String value;

    ActionTag(String value) {
      this.value = value;
    }

    @Override
    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return value;
    }
  }

  public enum PermissionPattern
      implements GetNameValue<String> {

    DOMAIN_APP_BASE("domain_app", false, "domain:app", PTag.COLON),
    DOMAIN_APP_CREATE("domain_app_create", true, DOMAIN_APP_BASE, ActionTag.CREATE),
    DOMAIN_APP_READ("domain_app_create", true, DOMAIN_APP_BASE, ActionTag.READ),
    DOMAIN_APP_UPDATE("domain_app_create", true, DOMAIN_APP_BASE, ActionTag.UPDATE),
    DOMAIN_APP_DELETE("domain_app_create", true, DOMAIN_APP_BASE, ActionTag.DELETE),
    DOMAIN_APP_ASSIGN_APP_ADMIN("domain_app_assign_app_admin", true, DOMAIN_APP_BASE,
        ActionTag.ASSIGN, ":app_admin"),


    APP_BASE("app", false, "app", PTag.COLON),
    APP_USER_CONTROL("app_user_control", true, APP_BASE, "user:control:", PTag.APP_ID),


    DISTANCE_CHECK("distance_check", true, "distance:check:", PTag.APP_ID),

    ;

    private final String basePattern;
    private final String name;
    private final boolean persist;

    PermissionPattern(String name, Boolean persist, Object... patterns) {

      this.persist = persist;
      this.name = name.toLowerCase();
      StringBuilder sb = new StringBuilder();

      for (Object pattern : patterns) {
        sb.append(pattern.toString().toLowerCase());
      }

      this.basePattern = sb.toString();
    }

    @Override
    public String getValue() {
      return basePattern;
    }

    @Override
    public String getName() {
      return name;
    }

    public boolean isPersist() {
      return persist;
    }

    public String patternAppend(String toAppend) {
      return basePattern + toAppend.toLowerCase();
    }

    @Override
    public String toString() {
      return basePattern;
    }
  }


  public enum Role
      implements GetName {

    DOMAIN_APP_MANAGEMENT("DOMAIN_APP_MANAGEMENT",
        PermissionPattern.DOMAIN_APP_CREATE,
        PermissionPattern.DOMAIN_APP_BASE,
        PermissionPattern.DOMAIN_APP_CREATE,
        PermissionPattern.DOMAIN_APP_READ,
        PermissionPattern.DOMAIN_APP_UPDATE,
        PermissionPattern.DOMAIN_APP_DELETE,
        PermissionPattern.DOMAIN_APP_ASSIGN_APP_ADMIN
    ),


    APP_MANAGEMENT("APP_MANAGEMENT",
        PermissionPattern.APP_BASE,
        PermissionPattern.APP_USER_CONTROL

    ),


    ORDER_MANAGEMENT("ORDER_MANAGEMENT"

    ),


    ORDER("ORDER"

    ),

    ;

    private String name;
    private PermissionPattern[] permissions;

    Role(String name, PermissionPattern... permissions) {
      this.name = name;
      this.permissions = permissions;
    }

    @Override
    public String getName() {
      return name;
    }

    public PermissionPattern[] getPermissions() {
      return permissions;
    }
  }

  public enum RoleGroup
      implements GetName {

    SUPER_ADMIN("SUPER_ADMIN", Role.DOMAIN_APP_MANAGEMENT),

    APP_ADMIN("APP_ADMIN", Role.APP_MANAGEMENT),


    APP_SERVICE_PROVIDER("APP_SERVICE_PROVIDER"),


    APP_CUSTOMER("APP_CUSTOMER"),


    APP_ACCOUNTANT("APP_ACCOUNTANT");

    private String name;
    private Role[] roles;

    RoleGroup(String name, Role... roles) {
      this.name = name;
      this.roles = roles;
    }

    @Override
    public String getName() {
      return name;
    }

    public Role[] getRoles() {
      return roles;
    }
  }

  private XXSecurityRealmTemplate() {

  }

}
