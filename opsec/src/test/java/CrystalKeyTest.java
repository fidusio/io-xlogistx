import io.xlogistx.opsec.OPSecUtil;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.util.SUS;
import org.zoxweb.shared.util.SharedBase64;
import org.zoxweb.shared.util.SharedStringUtil;

import javax.crypto.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class CrystalKeyTest {


    public static final String KYBER_PUB_KEY_B64 = "MIIDMjALBglghkgBZQMEBAEDggMhAGzcCIWTOQl1t2tDJSR0yIQ0EPy4prQnPq08fAIEMfmgKFBxn7lJv/VLb6QSdmYyCBwIZomGdGtRdYpWW852xgdyvTK6mXfVKEq5DHlzfftYZ5inqAmBwSWrL1i6m7hbExvBbeyLmdxwLrSGS/CEaz4SxmZqXuCbrzQJuOmJqaA3DM+pFW3xochUXYjRX/vpREikIVi3QNEBWS7GdSSRkLpMsgcF0ERCcVUItH2qWJugbFhkmvtRxqj4auN6Nc9AakWKNMqGK2aVTGU0ivlKFlyVcsdouGZhkH+TqtqbpkIjI9UxOvM1sb/3Bj0Sw70EtEBgVavjeMbjF6/GWMxUFtxCTKeSNxh4CDdLm+UjZFkGFafkbAHoa3uMBhhcRoa6x3u5iMuYoK+pW10MTGsqxxlgxseoIF05QUI1vzwMGvkKZARFF21LA50sjP4cq0TzFL6HcD7GbQFkwGTxhyRXbOKoQgxQlXk4Mp8okZezgJeUYLCDiU76eCABa90zVZGza6liLqBJO+4AimQKTBx2fv7cNiS4THv8KM0ae2ZoJilgE3O2yiRRa+E7bJNlVFqFQIJQCOMZE5OrC8jDeC+cRw5RVWnFamAUrFUpVXFoBSMDA70yUO7wxzDyrmFVdnMqOasqU6lMJainhxNhzU2LvpNwTNRDh3MymNhamWf3AEnjWtShA0pUMdDUDXnnhzs0WHPkWdGSsXIzLVIsPjQGZ+baVKs5EKhswE6Bc7srhy6QXa5LLFJSYDWZyfFExll2HIaaiANwEb4TEVBmpbtER/j0d+KlzLbGceQWSLcrN8S6jjO1F7kBXYWqACb7u1zMBmdgMJ4ZmgWjauj0jPdckdzBGyLJZsuFRUOUpPpzlOgIplyAwPEHmFWqKkc1vd3cSjRcv8kwEAcaPFOluLkkgorDoBpbQrHTjD+5GCoxXwVGhSl7N7gRaYdLmWP6JgUDK9rKH9qHm9DxSecpDeeKuZMYrXy4bMDJJZLEFM0CLXiyFyYrlQQEXK1jfVwVIMrFT0tcEHwOfFGkBGKE85mn2qWGbrHn98cLiBUJNodawzCv";
    public static final String KYBER_PRIV_KEY_B64 = "MFQCAQAwCwYJYIZIAWUDBAQBBEIEQI/ZBZPU3YtE+dqKLHnpsqJaAY/D+BrWNZWo+pNOcl/QcoMd1Zhem3F9cX6z3vn3MUApJPds+VOIOdwBLD8oN4s=";
    public static final String AES_KEY_B64 = "CJCDR2W5SspyxSkw2WWxUAvvFRiH/bW3d2Arbn8I3Zo=";
    @BeforeAll
    public static void first()
    {
        OPSecUtil.init();
    }

    @Test
    public  void testKeyWrapping() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidAlgorithmParameterException {
//        KeyPair kp = CryptoUtil.toKeyPair("kyber", "BCPQC", KYBER_PUB_KEY_B64, KYBER_PRIV_KEY_B64);
//        SecretKey aes = CryptoUtil.toSecretKey(SharedBase64.decode(AES_KEY_B64), "AES");
//        Cipher kyberWrapCipher = Cipher.getInstance("Kyber", "BCPQC");
//
//        for (int i = 0; i < 10; i++)
//        {
//            kyberWrapCipher.init(Cipher.WRAP_MODE, kp.getPublic(), new SecureRandom());
//            byte[] wrappedAesKeyBytes = kyberWrapCipher.wrap(aes);
//            System.out.println(wrappedAesKeyBytes.length + " Wrapped AES Key : " + SharedStringUtil.bytesToHex(wrappedAesKeyBytes));
//            // 5. Unwrap the AES key using Kyber in UNWRAP_MODE
//            Cipher kyberUnwrapCipher = Cipher.getInstance("Kyber", "BCPQC");
//            kyberUnwrapCipher.init(Cipher.UNWRAP_MODE, kp.getPrivate());
//            Key unwrappedAesKey = kyberUnwrapCipher.unwrap(wrappedAesKeyBytes, "AES", Cipher.SECRET_KEY);
//
//            System.out.println("[" + i + "] Are keys equals: " + unwrappedAesKey.equals(aes));
//        }

        KeyPair kp = CryptoUtil.toKeyPair("kyber", "BCPQC", KYBER_PUB_KEY_B64, KYBER_PRIV_KEY_B64);
        SecretKey aes = CryptoUtil.toSecretKey(SharedBase64.decode(AES_KEY_B64), "AES");

        for (int i = 0; i < 10; i++)
        {
            byte[] wrappedAesKeyBytes = OPSecUtil.encryptCKAESKey(kp.getPublic(), aes);
            System.out.println(wrappedAesKeyBytes.length + " Wrapped AES Key : " + SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT, wrappedAesKeyBytes));
            // 5. Unwrap the AES key using Kyber in UNWRAP_MODE
            Key unwrappedAesKey = OPSecUtil.decryptCKAESKey(kp.getPrivate(), wrappedAesKeyBytes);
            assert(SUS.equals(aes.getEncoded(), unwrappedAesKey.getEncoded()));
            System.out.println("[" + i + "] Are keys equals: " + aes.equals(unwrappedAesKey));
        }
    }
    @Test
    public void testKeyber() throws Exception {
        // 1. Add the Bouncy Castle providers (regular + PQC)

        // 2. Generate a 256-bit AES key
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        aesKeyGen.init(256);
        SecretKey originalAesKey = aesKeyGen.generateKey();
        byte[] originalAesKeyBytes = originalAesKey.getEncoded();
        System.out.println("Original AES Key " + SUS.toCanonicalID(',', originalAesKey.getAlgorithm(), originalAesKey.getFormat() )+ " : " + SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT, originalAesKeyBytes));

        // 3. Generate a Kyber key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        // You can choose kyber512, kyber768, or kyber1024
        kpg.initialize(KyberParameterSpec.kyber512, new SecureRandom());
        KeyPair kyberKp = kpg.generateKeyPair();
        PublicKey kyberPub = kyberKp.getPublic();
        PrivateKey kyberPriv = kyberKp.getPrivate();

        // 4. Wrap the AES key using Kyber in WRAP_MODE
        Cipher kyberWrapCipher = Cipher.getInstance("Kyber", "BCPQC");
        kyberWrapCipher.init(Cipher.WRAP_MODE, kyberPub, new SecureRandom());
        byte[] wrappedAesKeyBytes = kyberWrapCipher.wrap(originalAesKey);
        System.out.println( wrappedAesKeyBytes.length + " Wrapped AES Key : " + SharedStringUtil.bytesToHex(wrappedAesKeyBytes));
        // 5. Unwrap the AES key using Kyber in UNWRAP_MODE
        Cipher kyberUnwrapCipher = Cipher.getInstance("Kyber", "BCPQC");
        kyberUnwrapCipher.init(Cipher.UNWRAP_MODE, kyberPriv);
        Key unwrappedAesKey = kyberUnwrapCipher.unwrap(wrappedAesKeyBytes, "AES", Cipher.SECRET_KEY);

        // 6. Compare the original and unwrapped key bytes
        byte[] unwrappedAesKeyBytes = unwrappedAesKey.getEncoded();
        System.out.println("Unwrapped AES Key: " + SharedStringUtil.bytesToHex(unwrappedAesKeyBytes));

        boolean keysMatch = Arrays.equals(originalAesKeyBytes, unwrappedAesKeyBytes);
        System.out.println("Do the original and unwrapped AES keys match? " + keysMatch);


//        keyPairRegen();
//        testKeyWrapping();
//        dilithiumTest();
    }


    @Test
    public void keyPairRegen() throws Exception {
        // 1. Add the Bouncy Castle providers (regular + PQC).


        // 2. Generate a Kyber key pair.
        //    Available specs: kyber512, kyber768, or kyber1024.
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");
//        kpg.initialize(KyberParameterSpec.kyber512, new SecureRandom());
//        KeyPair kp = kpg.generateKeyPair();

        KeyPair kp = CryptoUtil.generateKeyPair("Kyber", "BCPQC", KyberParameterSpec.kyber512, null);

        PublicKey originalPublicKey = kp.getPublic();
        PrivateKey originalPrivateKey = kp.getPrivate();
        SecretKeyWithEncapsulation skwe = OPSecUtil.generateCKEncryptionKey(originalPublicKey);
        System.out.println(SUS.toCanonicalID(',', skwe.getEncoded().length, skwe.getEncapsulation().length));
        byte[] aesKey = skwe.getEncoded();
        SecretKeyWithEncapsulation regenSKWE = OPSecUtil.extractCKDecryptionKey(originalPrivateKey, skwe.getEncapsulation());
        assert SUS.equals(aesKey, regenSKWE.getEncoded());
        assert SUS.equals(skwe.getEncapsulation(), regenSKWE.getEncapsulation());

        System.out.println("KEM origin key: " +SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT, skwe.getEncapsulation()));
        System.out.println("KEM regen key: " +SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT, regenSKWE.getEncapsulation()));

        // Print them out just to show they're generated.
        System.out.println("Original Public Key  (object): " + originalPublicKey);
        System.out.println("Original Private Key (object): " + originalPrivateKey);

        // 3. Convert each key to a byte array and then Base64-encode those bytes.
        //    - Public keys are typically encoded in X.509 format
        //    - Private keys are typically encoded in PKCS#8 format
        byte[] pubKeyBytes = originalPublicKey.getEncoded();
        byte[] privKeyBytes = originalPrivateKey.getEncoded();

        String pubKeyBase64 = SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT, pubKeyBytes);
        String privKeyBase64 = SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT,privKeyBytes);

        System.out.println("\nSaved Public Key  (Base64): " + pubKeyBase64);
        System.out.println("Saved Private Key (Base64): " + privKeyBase64);

        /*
         * Imagine at this point, you persist these strings somewhere (file, DB, etc.).
         * We will now DEMONSTRATE how to reload them as key objects.
         */

        // 4. Decode the Base64 strings back to raw bytes.
//        byte[] pubKeyBytesReloaded = SharedBase64.decode(pubKeyBase64);
//        byte[] privKeyBytesReloaded = SharedBase64.decode(privKeyBase64);
//
//        // 5. Create KeyFactory for "Kyber", using the Bouncy Castle PQC provider.
//        KeyFactory kf = KeyFactory.getInstance("Kyber", "BCPQC");
//
//        // 6. Wrap those bytes into proper EncodedKeySpec objects.
//        //    - Public key uses X509EncodedKeySpec
//        //    - Private key uses PKCS8EncodedKeySpec
//        EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytesReloaded);
//        EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKeyBytesReloaded);
//
//        // 7. Re-generate (decode) the keys from the specs.
//        PublicKey regeneratedPublicKey = kf.generatePublic(pubKeySpec);
//        PrivateKey regeneratedPrivateKey = kf.generatePrivate(privKeySpec);
        KeyPair regenKeyPair = CryptoUtil.toKeyPair("kyber", "BCPQC", pubKeyBase64, privKeyBase64);

        // 8. Check that the regenerated keys match the originals (by comparing encoded bytes).
        boolean pubKeysMatch  = SUS.equals(originalPublicKey.getEncoded(), regenKeyPair.getPublic().getEncoded());
        boolean privKeysMatch = SUS.equals(originalPrivateKey.getEncoded(), regenKeyPair.getPrivate().getEncoded());

        System.out.println("\nRegenerated Public Key  (object): " + regenKeyPair.getPublic());
        System.out.println("Regenerated Private Key (object): " + regenKeyPair.getPrivate());

        System.out.println("\nDo public keys match?  " + pubKeysMatch);
        System.out.println("Do private keys match? " + privKeysMatch);

        // In an actual application, you'd store these key strings securely
        // and retrieve them when you need to do encryption/decryption with Kyber.
    }

    @Test
    public void dilithiumTest() throws Exception {
        // Add BC providers (including PQC)


        // Generate Dilithium key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", "BCPQC");
        kpg.initialize(DilithiumParameterSpec.dilithium2, CryptoUtil.defaultSecureRandom());
        KeyPair kp = kpg.generateKeyPair();
        PublicKey pub = kp.getPublic();
        PrivateKey priv = kp.getPrivate();

        // Create a message
        byte[] message = "Hello from post-quantum world!".getBytes();

        // Sign the message
        Signature signer = Signature.getInstance("Dilithium", "BCPQC");
        signer.initSign(priv, new SecureRandom());
        signer.update(message);
        byte[] signature = signer.sign();

        byte[] sign2 = CryptoUtil.sign(CryptoConst.SignatureAlgo.CRYSTALS_DILITHIUM, priv, message);

        // Verify the signature
        Signature verifier = Signature.getInstance("Dilithium", "BCPQC");
        verifier.initVerify(pub);
        verifier.update(message);
        boolean isValid = verifier.verify(signature);

        System.out.println("Signature valid? " + isValid);

        System.out.println("Signature valid? " + CryptoUtil.verify(CryptoConst.SignatureAlgo.CRYSTALS_DILITHIUM, pub, message, signature));
        System.out.println("Signature " + signature.length + "\n" + SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT, signature));
        System.out.println("Signature valid? " + CryptoUtil.verify(CryptoConst.SignatureAlgo.CRYSTALS_DILITHIUM, pub, message, sign2) );
        System.out.println("Signature " + sign2.length + "\n" + SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT, sign2));
    }
}

