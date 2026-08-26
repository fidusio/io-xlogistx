import io.xlogistx.opsec.OPSecUtil;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.security.SecUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.util.SUS;
import org.zoxweb.shared.util.SharedBase64;
import org.zoxweb.shared.util.SharedStringUtil;

import javax.crypto.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class PQCKeyTest {

    public static final LogWrapper log = new LogWrapper(PQCKeyTest.class).setEnabled(true);

    // ML-KEM-512 key pair (X.509/PKCS#8 encodings, BC "BC" provider)
    public static final String ML_KEM_PUB_KEY_B64 = "MIIDMjALBglghkgBZQMEBAEDggMhALsGHnHxHzC1Kx0Qr1CxDIGbFQUsiQRZUNjlcogwIkizB7D1K2a0IaQyE1/pYMODpUSgLFAhFuyJTvJiYXRLN68nMxwQyZD1L5s4rJmUQvWAIzyUWHaKkgDJvyF5mEkjkIvLPOoION21B75LDBfCuVJJZW/4Sss5A2RjjcXZSQgzP6dED6TVkPRKRxCFJt3GybpBlJ4EAkinPe7cADJyit82hBd5LVIqO4zQMvBYFrk4URCBmA9GfPWgH2VjQbNImfpQLAMxjnLSOywxRmeVFkXsKB96lA64UCVzE6KaQi0oaC7TQ6Gpnrx5y0QgIixXgRdktJDsWqjWNb36nae2lZ7MJl5UhXnSmET1zvKyGoUiIx7rKoABLBFnQBwULoD8mCtjSEPomOubG3Snau4DYCUgJuJjRS/DMcwCHb/VagRjKfOCFm8ZXjUZXMrcrOD0PvL3Hnt6jt1ss4BnJIecLOz7idfDmgNcVH0EdoVZzzDCQ2ykmziTYzqhHoo5xzqlQHISL1HEI5F1ALS4uSmao5/MPCiYoJoRzdyTNlYEwe0WM7JwjVtBv//puUJXPfT0JrCGLS6RMkk8yhSWHTtyq0XWpv28PY8LPlM5UjVVO+NHhj6IConzmEnTqt27X3b3XiOyLP/2PpcIarPGQSXCgUH8JiaBgLeMrt8Ag60mARS2FCnnfvV8LA8roS8KRxRoctErTnj5snnDYa1IM1mFhODBfYyLHHpqiBawK5ZpTtD1b7b0uXpJhk2Xd2UlkbhrhT6XEIWRerJ3VUp1D50YCCaILu9InynLmVGaq0zlQLoVNSOZy5vgLYzUAKXpglLixLc8SbPSj6XZaeAzyS6UMgIFODtAOWgZcCVUPOQEQZhjUlqXKoYCq8n0lb7MrDcVzPX6MuCgzPmWsaxozwOTUIqrpau0zZJASRkbXEzyAOIDvZiqYN6TUC9zw/C3sQeSfYdxt2pkZlKHQEUUcX0HxLWDLWKqXO9qlHGDnrAXTFj2ppCJzfkRL3pEThwyBUrXpojZLMJm28Ey1/DVCn2X0ShI37ykIfE9hpBgoRehQ+d0";
    public static final String ML_KEM_PRIV_KEY_B64 = "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";
    public static final String AES_KEY_B64 = "ohU+mCHxMhLyBuvjVaVfnmWOSfylqNHVgtIREQ0UavQ=";
    @BeforeAll
    public static void first()
    {
        OPSecUtil.singleton();
        log.getLogger().info("********************************************************************************************************************************");
    }

    @Test
    public  void testKeyWrapping() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidAlgorithmParameterException {
        KeyPair kp = OPSecUtil.SINGLETON.toKeyPair(CryptoConst.ML_KEM, SecUtil.BC_PROVIDER, ML_KEM_PUB_KEY_B64, ML_KEM_PRIV_KEY_B64);
        SecretKey aes = CryptoUtil.toSecretKey(SharedBase64.decode(AES_KEY_B64), "AES");

        for (int i = 0; i < 10; i++)
        {
            byte[] wrappedAesKeyBytes = OPSecUtil.SINGLETON.encryptCKAESKey(kp.getPublic(), aes);
            log.getLogger().info(wrappedAesKeyBytes.length + " Wrapped AES Key : " + SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT, wrappedAesKeyBytes));
            log.getLogger().info("");
            // 5. Unwrap the AES key using ML-KEM in UNWRAP_MODE
            Key unwrappedAesKey = OPSecUtil.SINGLETON.decryptCKAESKey(kp.getPrivate(), wrappedAesKeyBytes);
            assert(SUS.equals(aes.getEncoded(), unwrappedAesKey.getEncoded()));
            log.getLogger().info("[" + i + "] Are keys equals: " + aes.equals(unwrappedAesKey) + " aes key length: " + unwrappedAesKey.getAlgorithm() + " " + unwrappedAesKey.getFormat() + " " + unwrappedAesKey.getEncoded().length);
        }
    }

    public void testMLKEM() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        // 1. Add the Bouncy Castle providers

        // 2. Generate a 256-bit AES key
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        aesKeyGen.init(256);
        SecretKey originalAesKey = aesKeyGen.generateKey();
        byte[] originalAesKeyBytes = originalAesKey.getEncoded();
        log.getLogger().info("Original AES Key " + SUS.toCanonicalID(',', originalAesKey.getAlgorithm(), originalAesKey.getFormat() )+ " : " + SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT, originalAesKeyBytes));

        // 3. Generate an ML-KEM key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(CryptoConst.ML_KEM, SecUtil.BC_PROVIDER);
        // You can choose ml_kem_512, ml_kem_768, or ml_kem_1024
        kpg.initialize(MLKEMParameterSpec.ml_kem_512, new SecureRandom());
        KeyPair kemKp = kpg.generateKeyPair();
        PublicKey kemPub = kemKp.getPublic();
        PrivateKey kemPriv = kemKp.getPrivate();

        // 4. Wrap the AES key using ML-KEM in WRAP_MODE
        Cipher kemWrapCipher = Cipher.getInstance(CryptoConst.ML_KEM, SecUtil.BC_PROVIDER);
        kemWrapCipher.init(Cipher.WRAP_MODE, kemPub, new SecureRandom());
        byte[] wrappedAesKeyBytes = kemWrapCipher.wrap(originalAesKey);
        log.getLogger().info( wrappedAesKeyBytes.length + " ML-KEM AES Encryption : " + SharedStringUtil.bytesToHex(wrappedAesKeyBytes));
        // 5. Unwrap the AES key using ML-KEM in UNWRAP_MODE
        Cipher kemUnwrapCipher = Cipher.getInstance(CryptoConst.ML_KEM, SecUtil.BC_PROVIDER);
        kemUnwrapCipher.init(Cipher.UNWRAP_MODE, kemPriv);
        Key unwrappedAesKey = kemUnwrapCipher.unwrap(wrappedAesKeyBytes, "AES", Cipher.SECRET_KEY);

        // 6. Compare the original and unwrapped key bytes
        byte[] unwrappedAesKeyBytes = unwrappedAesKey.getEncoded();
        log.getLogger().info("Unwrapped AES Key: " + SharedStringUtil.bytesToHex(unwrappedAesKeyBytes));

        boolean keysMatch = Arrays.equals(originalAesKeyBytes, unwrappedAesKeyBytes);
        log.getLogger().info("Do the original and unwrapped AES keys match? " + keysMatch);
    }


    @Test
    public void testMLKEMByReloadingBCProviders() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        testMLKEM();
        OPSecUtil.singleton();
        testMLKEM();

    }



    @Test
    public void keyPairGen()
        throws Exception
    {
        try
        {
            keyPairRegen_internal(1);
        }
        catch (InvalidKeySpecException e)
        {
            e.printStackTrace();


           keyPairRegen_internal(1);
        }
    }
    private void keyPairRegen_internal(int repeat) throws Exception {
        // 1. Generate an ML-KEM key pair.
        //    Available specs: ml_kem_512, ml_kem_768, or ml_kem_1024.
        for(int i = 0; i < repeat; i++) {
            KeyPair kp = OPSecUtil.SINGLETON.generateKeyPair(CryptoConst.ML_KEM, SecUtil.BC_PROVIDER, MLKEMParameterSpec.ml_kem_512, null);

            PublicKey originalPublicKey = kp.getPublic();
            PrivateKey originalPrivateKey = kp.getPrivate();
            SecretKeyWithEncapsulation skwe = OPSecUtil.SINGLETON.generateCKEncryptionKey(originalPublicKey);
            log.getLogger().info("Encoded key length " + skwe.getEncoded().length + " encapsulation length "  + skwe.getEncapsulation().length);
            byte[] aesKey = skwe.getEncoded();
            SecretKeyWithEncapsulation regenSKWE = OPSecUtil.SINGLETON.extractCKDecryptionKey(originalPrivateKey, skwe.getEncapsulation());
            assert SUS.equals(aesKey, regenSKWE.getEncoded());
            assert SUS.equals(skwe.getEncapsulation(), regenSKWE.getEncapsulation());

            log.getLogger().info("KEM origin key: " + SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT, skwe.getEncapsulation()));
            log.getLogger().info("KEM regen key: " + SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT, regenSKWE.getEncapsulation()));

            // Print them out just to show they're generated.
            log.getLogger().info("Original Public Key  (object): " + originalPublicKey);
            log.getLogger().info("Original Private Key (object): " + originalPrivateKey);

            // 2. Convert each key to a byte array and then Base64-encode those bytes.
            //    - Public keys are typically encoded in X.509 format
            //    - Private keys are typically encoded in PKCS#8 format
            byte[] pubKeyBytes = originalPublicKey.getEncoded();
            byte[] privKeyBytes = originalPrivateKey.getEncoded();

            String pubKeyBase64 = SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT, pubKeyBytes);
            String privKeyBase64 = SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT, privKeyBytes);

            log.getLogger().info("\nPUB-KEY: " + pubKeyBase64 + "\nPRI-KEY: " + privKeyBase64);

            /*
             * Imagine at this point, you persist these strings somewhere (file, DB, etc.).
             * We will now DEMONSTRATE how to reload them as key objects.
             */

            KeyPair regenKeyPair = null;

            regenKeyPair = OPSecUtil.SINGLETON.toKeyPair(CryptoConst.ML_KEM, SecUtil.BC_PROVIDER, pubKeyBase64, privKeyBase64);

            // 3. Check that the regenerated keys match the originals (by comparing encoded bytes).
            boolean pubKeysMatch = SUS.equals(originalPublicKey.getEncoded(), regenKeyPair.getPublic().getEncoded());
            boolean privKeysMatch = SUS.equals(originalPrivateKey.getEncoded(), regenKeyPair.getPrivate().getEncoded());

            log.getLogger().info("\nRegenerated Public Key  (object): " + regenKeyPair.getPublic());
            log.getLogger().info("Regenerated Private Key (object): " + regenKeyPair.getPrivate());

            log.getLogger().info("Do public keys match?  " + pubKeysMatch);
            log.getLogger().info("Do private keys match? " + privKeysMatch);
            log.getLogger().info(GSONUtil.toJSONDefault(regenKeyPair.getPublic()));


            log.getLogger().info("Run count: " + i);
        }




        // In an actual application, you'd store these key strings securely
        // and retrieve them when you need to do encryption/decryption with ML-KEM.
    }

    @Test
    public void mlDsaTest() throws Exception {
        // Generate ML-DSA key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(CryptoConst.ML_DSA, SecUtil.BC_PROVIDER);
        kpg.initialize(MLDSAParameterSpec.ml_dsa_44, SecUtil.defaultSecureRandom());
        KeyPair kp = kpg.generateKeyPair();
        PublicKey pub = kp.getPublic();
        PrivateKey priv = kp.getPrivate();

        // Create a message
        byte[] message = "Hello from post-quantum world!".getBytes();

        // Sign the message
        Signature signer = Signature.getInstance(CryptoConst.ML_DSA, SecUtil.BC_PROVIDER);
        signer.initSign(priv, new SecureRandom());
        signer.update(message);
        byte[] signature = signer.sign();

        byte[] sign2 = CryptoUtil.sign(CryptoConst.SignatureAlgo.ML_DSA, priv, message);

        // Verify the signature
        Signature verifier = Signature.getInstance(CryptoConst.ML_DSA, SecUtil.BC_PROVIDER);
        verifier.initVerify(pub);
        verifier.update(message);
        boolean isValid = verifier.verify(signature);
        assert isValid;

        log.getLogger().info("Signature valid? " + isValid);

        assert CryptoUtil.verify(CryptoConst.SignatureAlgo.ML_DSA, pub, message, signature);
        log.getLogger().info("Signature " + signature.length + "\n" + SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT, signature));
        assert CryptoUtil.verify(CryptoConst.SignatureAlgo.ML_DSA, pub, message, sign2);
        log.getLogger().info("Signature " + sign2.length + "\n" + SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT, sign2));
    }
}
