package io.xlogistx.shiro;

import org.junit.jupiter.api.Test;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.app.AppIDDefault;
import org.zoxweb.shared.security.PermissionInfo;
import org.zoxweb.shared.security.RoleInfo;

import java.io.IOException;

public class ShiroMetaModelTest {

    private static final String DOMAIN = "nodomain.com";
    private static final String APP = "noapp";

    @Test
    public void permissions() throws IOException {
        PermissionInfo permission = new PermissionInfo("Read.Access", "user:read");
        permission.setAppIdDAO(new AppIDDefault(DOMAIN, APP));
        String json = GSONUtil.toJSONSimple(permission);
        System.out.println(json);
    }

    @Test
    public void roles() throws IOException {
        PermissionInfo permission = new PermissionInfo("Read.Access", "user:read");
        permission.setAppIdDAO(new AppIDDefault(DOMAIN, APP));

        RoleInfo role = new RoleInfo("user.role", null);
        role.setAppIdDAO(new AppIDDefault(DOMAIN, APP));
        role.addPermission(permission);

        String json = GSONUtil.toJSONSimple(role);

        System.out.println(json);
    }
}
