package io.xlogistx.opsec;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.zoxweb.server.security.KeyMakerProvider;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.util.NVGenericMap;

import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class SecretStoreTest {

    private static final char[] PW = "store-p@ss".toCharArray();

    @Test
    public void textSecrets_roundTripThroughFile_andNVGenericMap(@TempDir Path dir) throws Exception {
        File file = dir.resolve("vault.bcfks").toFile();
        try (SecretStore ss = SecretStore.create(file, PW)) {
            ss.put("db.url", "jdbc:postgresql://lax-2.xlogistx.io:5432/testdb")
              .put("db.user", "dbuser")
              .put("db.password", "héllo wörld ✓ p@ss")
              .put("smtp.password", "other");
            ss.save();
        }
        assertTrue(file.isFile() && file.length() > 0);
        assertFalse(new File(file.getPath() + ".tmp").exists(), "atomic save leaves no temp file");

        try (SecretStore ss = SecretStore.open(file, PW)) {
            assertEquals("dbuser", ss.get("db.user"));
            assertEquals("héllo wörld ✓ p@ss", ss.get("db.password"));
            assertNull(ss.get("nope"));
            assertEquals("dflt", ss.get("nope", "dflt"));
            assertEquals(SecretStore.EntryType.TEXT, ss.typeOf("db.user"));
            assertEquals(SecretStore.EntryType.NONE, ss.typeOf("nope"));

            NVGenericMap all = ss.toNVGenericMap();
            assertEquals(4, all.size());
            assertEquals("jdbc:postgresql://lax-2.xlogistx.io:5432/testdb", all.getValue("db.url"));
            NVGenericMap db = ss.toNVGenericMap("db.");
            assertEquals(3, db.size());
            assertNull(db.get("smtp.password"));
            assertEquals("dbuser", db.getValue("db.user"));

            // replace + remove
            ss.put("db.user", "dbuser2");
            assertTrue(ss.remove("smtp.password"));
            assertFalse(ss.remove("smtp.password"));
            ss.save();
        }
        try (SecretStore ss = SecretStore.open(file, PW)) {
            assertEquals("dbuser2", ss.get("db.user"));
            assertEquals(3, ss.size());
        }
    }

    @Test
    public void wrongPassword_isRejected(@TempDir Path dir) throws Exception {
        File file = dir.resolve("vault.bcfks").toFile();
        try (SecretStore ss = SecretStore.create(file, PW)) {
            ss.put("k", "v");
            ss.save();
        }
        assertThrows(IOException.class, () -> SecretStore.open(file, "wrong".toCharArray()));
        assertThrows(IOException.class, () -> SecretStore.create(file, PW), "create refuses an existing file");
        assertThrows(IOException.class, () -> SecretStore.open(dir.resolve("missing").toFile(), PW));
    }

    @Test
    public void putAll_fromMap_andStreamRoundTrip() throws Exception {
        NVGenericMap config = new NVGenericMap();
        config.add("db.user", "u");
        config.add("db.password", "p");
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (SecretStore ss = SecretStore.inMemory(PW)) {
            ss.putAll(config);
            assertThrows(IllegalStateException.class, ss::save, "no file bound");
            ss.save(bos);
        }
        try (SecretStore ss = SecretStore.load(new ByteArrayInputStream(bos.toByteArray()), PW)) {
            assertEquals("p", ss.get("db.password"));
            assertEquals(2, ss.toNVGenericMap().size());
        }
    }

    @Test
    public void mlDsa_selfSigned_signsAfterReload(@TempDir Path dir) throws Exception {
        File file = dir.resolve("vault.bcfks").toFile();
        try (SecretStore ss = SecretStore.create(file, PW)) {
            KeyPair kp = ss.createMLDSA("signer");
            assertEquals(SecretStore.DEFAULT_ML_DSA, kp.getPrivate().getAlgorithm());
            ss.createMLDSA("signer87", CryptoConst.ML_DSA_87, "CN=Signer 87, O=XLOGISTX", "1year");
            assertThrows(IllegalArgumentException.class, () -> ss.createMLDSA("bad", "ML-KEM-768", null, null));
            ss.save();
        }
        byte[] data = "hello".getBytes();
        try (SecretStore ss = SecretStore.open(file, PW)) {
            assertEquals(SecretStore.EntryType.KEY_PAIR, ss.typeOf("signer"));
            assertNull(ss.get("signer"), "a key pair is not a text secret");
            assertNull(ss.getSecretKey("signer"));
            assertEquals(0, ss.toNVGenericMap().size());

            KeyPair kp = ss.getKeyPair("signer");
            assertNotNull(kp);
            Signature s = Signature.getInstance(SecretStore.DEFAULT_ML_DSA, SecretStore.PROVIDER);
            s.initSign(kp.getPrivate());
            s.update(data);
            byte[] sig = s.sign();
            Signature v = Signature.getInstance(SecretStore.DEFAULT_ML_DSA, SecretStore.PROVIDER);
            v.initVerify(kp.getPublic());
            v.update(data);
            assertTrue(v.verify(sig));

            X509Certificate cert = ss.getCertificate("signer");
            assertEquals("CN=signer", cert.getSubjectX500Principal().getName());
            cert.verify(cert.getPublicKey(), SecretStore.PROVIDER);

            X509Certificate c87 = ss.getCertificate("signer87");
            assertEquals(CryptoConst.ML_DSA_87, ss.getPrivateKey("signer87").getAlgorithm());
            assertTrue(c87.getSubjectX500Principal().getName().contains("Signer 87"));
            long life = c87.getNotAfter().getTime() - c87.getNotBefore().getTime();
            assertTrue(life > 360L * 86400_000L && life < 370L * 86400_000L, "1year validity");
        }
    }

    @Test
    public void mlKem_encapsulatesAfterReload_ephemeralAndStoredSigner(@TempDir Path dir) throws Exception {
        File file = dir.resolve("vault.bcfks").toFile();
        try (SecretStore ss = SecretStore.create(file, PW)) {
            ss.createMLKEM("kem-alone");
            ss.createMLDSA("ca");
            ss.createMLKEM("kem-signed", "ML-KEM-1024", "ca", null, null);
            ss.put("db.user", "u");
            assertThrows(IllegalArgumentException.class, () -> ss.createMLKEM("x", null, "db.user", null, null), "signer must be ML-DSA");
            assertThrows(IllegalArgumentException.class, () -> ss.createMLKEM("x", null, "kem-alone", null, null), "a KEM key cannot sign");
            assertThrows(IllegalArgumentException.class, () -> ss.createMLKEM("x", "ML-DSA-65", null, null, null));
            assertFalse(ss.contains("x"), "rejected creates leave nothing behind");
            ss.save();
        }
        try (SecretStore ss = SecretStore.open(file, PW)) {
            for (String alias : new String[]{"kem-alone", "kem-signed"}) {
                KeyPair kp = ss.getKeyPair(alias);
                assertNotNull(kp, alias);
                SecretKeyWithEncapsulation enc = OPSecUtil.SINGLETON.generateCKEncryptionKey(kp.getPublic());
                SecretKeyWithEncapsulation dec = OPSecUtil.SINGLETON.extractCKDecryptionKey(kp.getPrivate(), enc.getEncapsulation());
                assertArrayEquals(enc.getEncoded(), dec.getEncoded(), alias);
            }
            assertEquals(SecretStore.DEFAULT_ML_KEM, ss.getPrivateKey("kem-alone").getAlgorithm());
            assertEquals("ML-KEM-1024", ss.getPrivateKey("kem-signed").getAlgorithm());

            Certificate[] alone = ss.getCertificateChain("kem-alone");
            assertEquals(1, alone.length);
            Certificate[] signed = ss.getCertificateChain("kem-signed");
            assertEquals(2, signed.length);
            X509Certificate ca = ss.getCertificate("ca");
            ((X509Certificate) signed[0]).verify(ca.getPublicKey(), SecretStore.PROVIDER);
            assertEquals(ca.getSubjectX500Principal(), ((X509Certificate) signed[0]).getIssuerX500Principal());
            assertEquals(1, ss.toNVGenericMap().size(), "only db.user is text");
        }
    }

    @Test
    public void secretKey_feedsKeyMakerProvider(@TempDir Path dir) throws Exception {
        File file = dir.resolve("vault.bcfks").toFile();
        byte[] encoded;
        try (SecretStore ss = SecretStore.create(file, PW)) {
            SecretKey key = ss.createSecretKey("master");
            encoded = key.getEncoded();
            assertEquals(32, encoded.length);
            ss.save();
        }
        try (SecretStore ss = SecretStore.open(file, PW)) {
            assertEquals(SecretStore.EntryType.SECRET_KEY, ss.typeOf("master"));
            assertArrayEquals(encoded, ss.getSecretKey("master").getEncoded());
            assertNull(ss.get("master"));
            KeyMakerProvider kmp = KeyMakerProvider.SINGLETON;
            kmp.setMasterSecretKey(ss.getKeyStore(), "master", new String(PW));
            assertArrayEquals(encoded, kmp.getMasterKey());
        }
    }

    @Test
    public void cli_createPutGetListRemove(@TempDir Path dir) throws Exception {
        String store = dir.resolve("cli.bcfks").toString();
        String pw = "store.password=" + new String(PW);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        PrintStream o = new PrintStream(out, true, "UTF-8");
        PrintStream e = new PrintStream(err, true, "UTF-8");

        assertEquals(SecretStore.EXIT_USAGE, SecretStore.run(o, e, "command=list"), "store missing");
        assertEquals(SecretStore.EXIT_USAGE, SecretStore.run(o, e, "store=" + store, pw), "command missing");
        assertEquals(SecretStore.EXIT_FAILURE, SecretStore.run(o, e, "store=" + store, pw, "command=list"), "no file yet");

        assertEquals(SecretStore.EXIT_OK, SecretStore.run(o, e, "store=" + store, pw, "command=create"), err.toString());
        assertEquals(SecretStore.EXIT_FAILURE, SecretStore.run(o, e, "store=" + store, pw, "command=create"), "exists");
        assertEquals(SecretStore.EXIT_OK, SecretStore.run(o, e, "store=" + store, pw, "command=put", "name=db.user", "value=dbuser"), err.toString());
        assertEquals(SecretStore.EXIT_OK, SecretStore.run(o, e, "store=" + store, pw, "command=put", "name=db.password", "value=s3cret"), err.toString());
        assertEquals(SecretStore.EXIT_OK, SecretStore.run(o, e, "store=" + store, pw, "command=ml-dsa", "alias=signer"), err.toString());
        assertEquals(SecretStore.EXIT_OK, SecretStore.run(o, e, "store=" + store, pw, "command=ml-kem", "alias=kem", "signer=signer"), err.toString());
        assertEquals(SecretStore.EXIT_OK, SecretStore.run(o, e, "store=" + store, pw, "command=secret-key", "alias=master"), err.toString());
        assertEquals(SecretStore.EXIT_USAGE, SecretStore.run(o, e, "store=" + store, pw, "command=put", "name=x"), "no console: value required");
        assertEquals(SecretStore.EXIT_FAILURE, SecretStore.run(o, e, "store=" + store, pw, "command=ml-kem", "alias=k2", "algo=ML-KEM-42"));

        out.reset();
        assertEquals(SecretStore.EXIT_OK, SecretStore.run(o, e, "store=" + store, pw, "command=get", "name=db.password"));
        assertEquals("s3cret", out.toString("UTF-8").trim());
        assertEquals(SecretStore.EXIT_FAILURE, SecretStore.run(o, e, "store=" + store, pw, "command=get", "name=signer"), "not text");

        out.reset();
        assertEquals(SecretStore.EXIT_OK, SecretStore.run(o, e, "store=" + store, pw, "command=list"));
        String listing = out.toString("UTF-8");
        assertTrue(listing.contains("db.user  TEXT") && listing.contains("signer  KEY_PAIR  ML-DSA-65")
                && listing.contains("kem  KEY_PAIR  ML-KEM-768") && listing.contains("master  SECRET_KEY  AES 256 bits")
                && listing.contains("5 entries"), listing);
        assertFalse(listing.contains("s3cret"), "list never prints values");

        assertEquals(SecretStore.EXIT_OK, SecretStore.run(o, e, "store=" + store, pw, "command=remove", "name=master"));
        assertEquals(SecretStore.EXIT_FAILURE, SecretStore.run(o, e, "store=" + store, pw, "command=remove", "name=master"));
        assertEquals(SecretStore.EXIT_FAILURE, SecretStore.run(o, e, "store=" + store, "store.password=wrong", "command=list"));

        try (SecretStore ss = SecretStore.open(new File(store), PW)) {
            assertEquals(Arrays.asList("db.password", "db.user", "kem", "signer"), new java.util.ArrayList<>(ss.aliases()));
            assertEquals(2, ss.toNVGenericMap().size());
            PrivateKey kem = ss.getPrivateKey("kem");
            assertEquals(SecretStore.DEFAULT_ML_KEM, kem.getAlgorithm());
            assertEquals(2, ss.getCertificateChain("kem").length);
        }
    }
}
