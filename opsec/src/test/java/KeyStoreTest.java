import io.xlogistx.opsec.OPSecUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.Test;
import org.zoxweb.shared.crypto.CryptoConst;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

public class KeyStoreTest {

    @Test
    public void testSelfSignedCreateKeyStore() throws Exception {
        KeyPair keyPair = OPSecUtil.SINGLETON.generateKeyPair(CryptoConst.PKInfo.EC_256, "BC");
        X509Certificate cert = OPSecUtil.SINGLETON.generateSelfSignedCertificate(keyPair,
                new X500Name("CN=XLOGISTX Test CA, O=XLOGISTX.IO, L=Los Angeles, C=US"),
                new X500Name("CN=testr.xlogistx.io, O=XLOGISTX.IO, L=Los Angeles, C=US"), "5year");

        KeyStore ks = OPSecUtil.SINGLETON.createKeyStore("toto", "password", keyPair.getPrivate(), cert);
        System.out.println(ks.aliases().nextElement());


    }

}
