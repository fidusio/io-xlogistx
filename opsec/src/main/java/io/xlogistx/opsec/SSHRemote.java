package io.xlogistx.opsec;


import okio.Path;
import org.zoxweb.shared.security.SShURI;
import org.zoxweb.shared.util.ParamUtil;
import org.zoxweb.shared.util.SUS;

import java.net.URI;
import java.security.KeyPair;
import java.util.Arrays;

public class SSHRemote {

    public static void main(String ...args) {
        try {
            ParamUtil.ParamMap params = ParamUtil.parse("=", args);

            String[] sshURIsParams = ParamUtil.parseWithSep(",", params.stringValue("ssh-uris"));
            //String password = params.stringValue("password", true);
            String command = params.stringValue("command");
            String pemKey = params.stringValue("pem", true);
            KeyPair[] keys = null;

            URI pemURI = null;
            if (pemKey != null) {
                try {
                    pemURI = new URI(pemKey);

                } catch (Exception e) {
                    pemURI = Path.get(pemKey).toFile().toURI();
                }
                keys = OPSecUtil.loadKeyPairFromPath(pemURI);
            }


            System.out.println("sshURIs: " + Arrays.toString(sshURIsParams));
            SShURI[] sshURIs = new SShURI[sshURIsParams.length];
            for (int i = 0; i < sshURIsParams.length; i++)
                sshURIs[i] = SShURI.parse(sshURIsParams[i]);


            for (SShURI h : sshURIs) {
                try {
                    if (SUS.isEmpty(h.credential) && keys != null)
                        System.out.println(h + "\n" + OPSecUtil.sshCommand(h, keys, command));
                    else if (!SUS.isEmpty(h.credential))
                        System.out.println(h + "\n" + OPSecUtil.sshCommand(h, command));
                    else
                        System.out.println(h + " has no credentials");
                } catch (Exception e) {
                    e.printStackTrace();
                    System.err.println("error for " + h);
                }
            }


        } catch (Exception e) {
            e.printStackTrace();

            System.err.println("Usage: ssh-uris=root[password or credential]@192.168.1.1,root@google.com:2022  [pem=google.privateKey.pem] command=\"ls -ls\"");
        }
    }
}
