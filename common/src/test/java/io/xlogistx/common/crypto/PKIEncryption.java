package io.xlogistx.common.crypto;


import org.junit.jupiter.api.Test;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.crypto.EncryptedData;
import org.zoxweb.shared.crypto.EncapsulatedKey;
import org.zoxweb.shared.util.*;

import javax.crypto.*;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class PKIEncryption {
    @Test
    public void eccKeyAgreement() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");


        ECGenParameterSpec ecsp = new ECGenParameterSpec("secp256k1");
        kpg.initialize(ecsp);

        KeyPair kpU = kpg.genKeyPair();
        PrivateKey privKeyU = kpU.getPrivate();
        PublicKey pubKeyU = kpU.getPublic();
        System.out.println("User U: " + privKeyU.toString());
        System.out.println("User U: " + pubKeyU.toString() + " size:" + pubKeyU.getEncoded().length);

        KeyPair kpV = kpg.genKeyPair();
        PrivateKey privKeyV = kpV.getPrivate();
        PublicKey pubKeyV = kpV.getPublic();
        System.out.println("User V: " + privKeyV.toString());
        System.out.println("User V: " + pubKeyV.toString());

        KeyAgreement ecdhU = KeyAgreement.getInstance("ECDH");
        ecdhU.init(privKeyU);
        ecdhU.doPhase(pubKeyV, true);

        KeyAgreement ecdhV = KeyAgreement.getInstance("ECDH");
        ecdhV.init(privKeyV);
        ecdhV.doPhase(pubKeyU, true);

        byte[] keySU = ecdhU.generateSecret();

        System.out.println("Secret computed by U: 0x" +
                (new BigInteger(1, keySU).toString(16)).toUpperCase());
        System.out.println("Size:" + keySU.length + ", " + SharedStringUtil.bytesToHex(keySU));


        System.out.println("Secret computed by V: 0x" +
                (new BigInteger(1, ecdhV.generateSecret()).toString(16)).toUpperCase());

    }


    @Test
    public void rsaEncryption() throws GeneralSecurityException, IOException {
        KeyPair kp = CryptoUtil.generateKeyPair("RSA", 2048);
        byte[] data = SharedStringUtil.getBytes("1234567890abcdefgklmnopqrstuvwxyz");
        byte[] encryptedData = CryptoUtil.encrypt(kp.getPublic(), data);
        NVGenericMap nvgm = new NVGenericMap();
        nvgm.add(new NVBlob("rsa", encryptedData));
        SecretKey aes = CryptoUtil.generateKey(CryptoConst.CryptoAlgo.AES, 256);
        EncryptedData edao = CryptoUtil.encryptData(new EncryptedData(), aes.getEncoded(), data);
        nvgm.add("aes", edao);
        String json = GSONUtil.toJSONGenericMap(nvgm, false, false, true);
        System.out.println(json);
        nvgm = GSONUtil.fromJSONGenericMap(json, null, null);
        System.out.println(GSONUtil.toJSONGenericMap(nvgm, false, false, true));
        System.out.println("RSA Encrypted data: " + encryptedData.length + ":" + SharedStringUtil.bytesToHex(encryptedData));
        System.out.println("AES Encrypted data: " + edao.getEncryptedData().length + ":" + SharedStringUtil.bytesToHex(edao.getEncryptedData()));
        byte[] decryptedData = CryptoUtil.decrypt(kp.getPrivate(), nvgm.getValue("rsa"));
        System.out.println("RSA Decrypted data: " + new String(decryptedData));
        System.out.println(new String(decryptedData));
        edao = (EncryptedData) nvgm.getValue("aes");
        decryptedData = CryptoUtil.decryptEncryptedData(edao, aes.getEncoded());
        System.out.println("Decrypted data: " + SharedStringUtil.bytesToHex(decryptedData));
        System.out.println(new String(decryptedData));

        System.out.println("Priv: " + SharedStringUtil.bytesToHex(kp.getPrivate().getEncoded()));
        System.out.println("Pub : " + SharedStringUtil.bytesToHex(kp.getPublic().getEncoded()));
        PublicKey pubGen = CryptoUtil.generatePublicKey("rsa", kp.getPublic().getEncoded());
        PrivateKey privGen = CryptoUtil.generatePrivateKey("rsa", kp.getPrivate().getEncoded());
        System.out.println("Priv: " + pubGen.equals(kp.getPublic()) + ":" + SharedStringUtil.bytesToHex(privGen.getEncoded()));
        System.out.println("Pub : " + privGen.equals(kp.getPrivate()) + ":" + SharedStringUtil.bytesToHex(pubGen.getEncoded()));
    }

//    @Test
//    public void eccEncryptionBC() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, ShortBufferException, IOException, NoSuchProviderException, InvalidAlgorithmParameterException {
//        Security.addProvider(new BouncyCastleProvider());
//
//        KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
//        ecKeyGen.initialize(new ECGenParameterSpec("secp256r1"));
//
//        KeyPair ecKeyPair = ecKeyGen.generateKeyPair();
//
//        Cipher iesCipher = Cipher.getInstance("ECIESwithAES-CBC");
//
//        iesCipher.init(Cipher.ENCRYPT_MODE, ecKeyPair.getPublic());
//
//        String message = "Hello World";
//
//        byte[] ciphertext = iesCipher.doFinal(message.getBytes());
//        System.out.println(SharedStringUtil.bytesToHex(ciphertext));
//
//
//        byte[] plaintext = CryptoUtil.decrypt(ecKeyPair.getPrivate(), "ECIESwithAES-CBC", iesCipher.getParameters(), ciphertext);
//        System.out.println(new String(plaintext));
//    }

    @Test
    public void eccKeyEncryption() throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, SignatureException {

        KeyPair kp = CryptoUtil.generateKeyPair("EC", 256);
        KeyAgreement selfV = KeyAgreement.getInstance("ECDH");
        selfV.init(kp.getPrivate());
        selfV.doPhase(kp.getPublic(), true);

        SecretKey keySelf = selfV.generateSecret("TlsPremasterSecret");
        System.out.println("key:" + SharedUtil.toCanonicalID(',', keySelf.getAlgorithm(), keySelf.getEncoded().length, keySelf.getFormat(), SharedStringUtil.bytesToHex(keySelf.getEncoded())));

        EncapsulatedKey ecd = CryptoUtil.createEncryptedKey(keySelf.getEncoded());
        System.out.println(GSONUtil.toJSON(ecd, true));

        byte[] data = SharedStringUtil.getBytes("Hello World of cipher and key makers. Matrix Neo and  LANA");
        System.out.println(SharedBase64.encodeAsString(SharedBase64.Base64Type.URL, data));
        System.out.println(SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT, data));
        EncryptedData encryptedData = CryptoUtil.encryptData(new EncryptedData(), keySelf.getEncoded(), data);
        String encryptedDataJson = GSONUtil.toJSON(encryptedData, true, false, true, SharedBase64.Base64Type.URL);
        encryptedData = GSONUtil.fromJSON(encryptedDataJson);
        System.out.println(encryptedDataJson);

        String b64EncData = SharedBase64.encodeAsString(SharedBase64.Base64Type.URL, encryptedData.getEncryptedData());
        SharedBase64.Base64Type b64Type = SharedBase64.detectType(b64EncData);
        System.out.println(b64Type + ":" + encryptedData.getEncryptedData().length + ":" + b64EncData.length()
                + ": " + b64EncData);
        System.out.println(SharedStringUtil.toString(CryptoUtil.decryptEncryptedData(encryptedData, keySelf.getEncoded())));

    }
}
