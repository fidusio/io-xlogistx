package io.xlogistx.opsec;


import okio.Path;
import org.zoxweb.shared.security.SShURI;
import org.zoxweb.shared.util.ParamUtil;

import java.net.URI;
import java.security.KeyPair;
import java.util.Arrays;

public class SSHRemote {

    public static void main(String... args) {
        try {
            ParamUtil.ParamMap params = ParamUtil.parse("=", args);
            System.out.println(params.toString());

            String[] sshURIsParams = ParamUtil.parseWithSep(",", params.stringValue("ssh-uris"));
            String password = params.stringValue("password", true);
            String command = params.stringValue("command");
            String pemKey = params.stringValue("pem", true);

            URI pemURI = null;
            if(password == null) {
                try {
                    pemURI = new URI(pemKey);

                } catch (Exception e) {
                    pemURI = Path.get(pemKey).toFile().toURI();
                }
            }


            System.out.println("sshURIs: " + Arrays.toString(sshURIsParams));
            SShURI[] sshURIs = new SShURI[sshURIsParams.length];
            for (int i = 0; i < sshURIsParams.length; i++)
                sshURIs[i] = SShURI.parse(sshURIsParams[i]);

            if (password != null)
                for (SShURI h : sshURIs) {
                    try {
                        System.out.println(h + "\n" + OPSecUtil.sshCommand(h, password, command));
                    } catch (Exception e) {
                        e.printStackTrace();
                        System.err.println("error for " + h);
                    }
                }
            if (pemKey != null) {
                KeyPair[] keys = OPSecUtil.loadKeyPairFromPath(pemURI);
                for (SShURI h : sshURIs) {
                    try {
                        System.out.println(h + "\n" + OPSecUtil.sshCommand(h, keys, command));
                    } catch (Exception e) {
                        e.printStackTrace();
                        System.err.println("error for " + h);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();

            System.err.println("Usage: ssh-uris=root@192.168.1.1,root@google.com:2022  [password=12345 or pem=google.privateKey.pem] command=\"ls -ls\"");
        }
    }
}
