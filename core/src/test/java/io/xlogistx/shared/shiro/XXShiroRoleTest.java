package io.xlogistx.shared.shiro;


import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class XXShiroRoleTest {

  @Test
  public void testShiroRole() {
    XXSecurityRealmTemplate.PermissionPattern[] permissions = XXSecurityRealmTemplate.Role.DOMAIN_APP_MANAGEMENT
        .getPermissions();
    assertNotNull(permissions);

    for (XXSecurityRealmTemplate.PermissionPattern permission : permissions) {
      System.out.println(permission);
    }
  }

}
