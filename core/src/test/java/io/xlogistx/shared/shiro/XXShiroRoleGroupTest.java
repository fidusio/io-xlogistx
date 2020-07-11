package io.xlogistx.shared.shiro;


import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class XXShiroRoleGroupTest {

  @Test
  public void testShiroRoleGroup() {
    XXSecurityRealmTemplate.Role[] roles = XXSecurityRealmTemplate.RoleGroup.SUPER_ADMIN.getRoles();
    assertNotNull(roles);

    for (XXSecurityRealmTemplate.Role role : roles) {
      System.out.println(role);
    }
  }

}
