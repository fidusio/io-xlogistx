package io.xlogistx.opsec.ssl;

import io.xlogistx.opsec.OPSecUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.io.SharedIOUtil;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Date;

public class SelfSignCert {
    public static KeyStore testSelfSignedCreateKeyStore() throws Exception {
        KeyPair keyPair = OPSecUtil.SINGLETON.generateKeyPair(CryptoConst.PKInfo.EC_256, "BC");
        X509Certificate cert = OPSecUtil.SINGLETON.generateSelfSignedCertificate(keyPair,
                new X500Name("CN=XLOGISTX Test CA, O=XLOGISTX.IO, L=Los Angeles, C=US"),
                new X500Name("CN=testr.xlogistx.io, O=XLOGISTX.IO, L=Los Angeles, C=US"), "5year");

        KeyStore ks = OPSecUtil.SINGLETON.createKeyStore("xlog-tester", "password", keyPair.getPrivate(), cert);
        return ks;
    }


    public static void main(String ...args)
    {
        OutputStream os = null;
        try {
            String filename = args[0];
            File file = new File(filename);
            System.out.println(file + " " + new Date(file.lastModified()));
            os = new FileOutputStream(file);
            testSelfSignedCreateKeyStore().store(os, "password".toCharArray());
            System.out.println(file + " " + new Date(file.lastModified()));

        }
        catch (Exception e) {
            e.printStackTrace();
        }
        finally {
            SharedIOUtil.close(os);
        }
    }

}
