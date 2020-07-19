package iot.xlogistx.shiro;

import org.junit.jupiter.api.Test;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.security.shiro.ShiroPermissionDAO;
import org.zoxweb.shared.security.shiro.ShiroRoleDAO;

import java.io.IOException;

public class ShiroMetaModelTest {

    private static final String DOMAIN = "nodomain.com";
    private static final String APP = "noapp";

    @Test
    public void permissions() throws IOException {
        ShiroPermissionDAO permission = new ShiroPermissionDAO(DOMAIN, APP,"Read.Access", null, "user:read");
        String json = GSONUtil.toJSONSimple(permission);
        System.out.println(json);
    }

    @Test
    public void roles() throws IOException {
        ShiroPermissionDAO permission = new ShiroPermissionDAO(DOMAIN, APP,"Read.Access", null, "user:read");

        ShiroRoleDAO role = new ShiroRoleDAO(DOMAIN, APP, "user.role");
        role.addPermissions(permission);

        String json = GSONUtil.toJSONSimple(role);

        System.out.println(json);
    }
}
