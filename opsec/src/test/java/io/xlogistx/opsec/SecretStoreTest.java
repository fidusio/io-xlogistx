package io.xlogistx.opsec;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.junit.jupiter.api.Assumptions;
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
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class SecretStoreTest {

    private static final char[] PW = "store-p@ss".toCharArray();
    private static final String SCRYPT = "scrypt N=" + SecretStore.SCRYPT_COST + " r=" + SecretStore.SCRYPT_BLOCK_SIZE
            + " p=" + SecretStore.SCRYPT_BLOCK_SIZE;
    private static final String PBKDF2 = "PBKDF2-HMAC-SHA512 iterations=" + SecretStore.PBKDF2_ITERATIONS;
    /** What Bouncy Castle writes when no KDF is asked for: every store made before 2026-11-10. */
    private static final String LEGACY = "PBKDF2-HMAC-SHA512 iterations=51200";

    @Test
    public void kdf_newStoreIsScrypt_andLaterSavesKeepIt(@TempDir Path dir) throws Exception {
        File file = dir.resolve("vault.bcfks").toFile();
        try (SecretStore ss = SecretStore.create(file, PW)) {
            assertEquals(SCRYPT, SecretStore.describeKDF(file), "written by create");
            ss.put("k", "v");
            ss.save();
        }
        assertEquals(SCRYPT, SecretStore.describeKDF(file));
        try (SecretStore ss = SecretStore.open(file, PW)) {
            assertEquals("v", ss.get("k"));
            ss.put("k2", "v2");
            ss.save();
        }
        assertEquals(SCRYPT, SecretStore.describeKDF(file), "a reopened store keeps its KDF");
        assertThrows(IOException.class, () -> SecretStore.open(file, "wrong-password".toCharArray()));

        File pbkdf2 = dir.resolve("pbkdf2.bcfks").toFile();
        try (SecretStore ss = SecretStore.create(pbkdf2, PW, SecretStore.KDF.PBKDF2)) {
            ss.put("k", "v");
            ss.save();
        }
        assertEquals(PBKDF2, SecretStore.describeKDF(pbkdf2));
        try (SecretStore ss = SecretStore.open(pbkdf2, PW)) {
            assertEquals("v", ss.get("k"));
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (SecretStore ss = SecretStore.inMemory(PW)) {
            ss.save(bos);
        }
        assertEquals(SCRYPT, SecretStore.describeKDF(bos.toByteArray()), "an in-memory store too");
        assertThrows(IOException.class, () -> SecretStore.describeKDF("not a store".getBytes()));
        assertEquals(SecretStore.KDF.SCRYPT, SecretStore.KDF.lookup(null));
        assertEquals(SecretStore.KDF.PBKDF2, SecretStore.KDF.lookup(" PBKDF2 "));
        assertThrows(IllegalArgumentException.class, () -> SecretStore.KDF.lookup("md5"));
    }

    @Test
    public void legacyStore_opensAndSavesUnchanged_thenUpgrades(@TempDir Path dir) throws Exception {
        // a store as SecretStore wrote it before 2026-11-10 (plain BCFKS load/store), with a password
        // shorter than a new store accepts
        char[] oldPW = "short".toCharArray();
        File file = dir.resolve("legacy.bcfks").toFile();
        OPSecUtil.singleton();
        KeyStore ks = KeyStore.getInstance(SecretStore.TYPE, SecretStore.PROVIDER);
        ks.load(null, oldPW);
        try (OutputStream os = Files.newOutputStream(file.toPath())) {
            ks.store(os, oldPW);
        }
        assertEquals(LEGACY, SecretStore.describeKDF(file));

        byte[] master;
        try (SecretStore ss = SecretStore.open(file, oldPW)) {
            ss.put("db.user", "u");
            master = ss.createSecretKey("master").getEncoded();
            ss.save();
        }
        assertEquals(LEGACY, SecretStore.describeKDF(file), "saving a legacy store does not change its KDF");

        try (SecretStore ss = SecretStore.open(file, oldPW)) {
            assertEquals("u", ss.get("db.user"));
            ss.upgradeKDF(null).save();
        }
        assertEquals(SCRYPT, SecretStore.describeKDF(file), "upgraded to the default");
        try (SecretStore ss = SecretStore.open(file, oldPW)) {
            assertEquals("u", ss.get("db.user"));
            assertArrayEquals(master, ss.getSecretKey("master").getEncoded());
            ss.put("db.password", "p");
            ss.save();
        }
        assertEquals(SCRYPT, SecretStore.describeKDF(file), "and it stays");

        // the same from the command line
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        PrintStream o = new PrintStream(out, true, "UTF-8");
        PrintStream e = new PrintStream(err, true, "UTF-8");
        String store = "store=" + file;
        String pw = "store.password=" + new String(oldPW);
        assertEquals(SecretStore.EXIT_FAILURE, SecretStore.run(o, e, store, pw, "command=upgrade", "kdf=md5"));
        assertEquals(SCRYPT, SecretStore.describeKDF(file), "a refused upgrade writes nothing");
        assertEquals(SecretStore.EXIT_OK, SecretStore.run(o, e, store, pw, "command=upgrade", "kdf=pbkdf2"), err.toString());
        assertEquals(PBKDF2, SecretStore.describeKDF(file));
        assertTrue(out.toString("UTF-8").contains(SCRYPT + " -> " + PBKDF2), out.toString("UTF-8"));
        out.reset();
        assertEquals(SecretStore.EXIT_OK, SecretStore.run(o, e, store, pw, "command=list"), err.toString());
        assertTrue(out.toString("UTF-8").contains("kdf " + PBKDF2), out.toString("UTF-8"));
        out.reset();
        assertEquals(SecretStore.EXIT_OK, SecretStore.run(o, e, store, pw, "command=get", "name=db.password"), err.toString());
        assertEquals("p", out.toString("UTF-8").trim());
    }

    @Test
    public void newStore_refusesShortPassword(@TempDir Path dir) throws Exception {
        char[] shortPW = new char[SecretStore.MIN_PASSWORD_LENGTH - 1];
        Arrays.fill(shortPW, 'x');
        File file = dir.resolve("vault.bcfks").toFile();
        assertThrows(IllegalArgumentException.class, () -> SecretStore.create(file, shortPW));
        assertThrows(IllegalArgumentException.class, () -> SecretStore.openOrCreate(file, shortPW));
        assertThrows(IllegalArgumentException.class, () -> SecretStore.inMemory(shortPW));
        assertFalse(file.exists(), "nothing is written");

        ByteArrayOutputStream err = new ByteArrayOutputStream();
        PrintStream o = new PrintStream(new ByteArrayOutputStream(), true, "UTF-8");
        PrintStream e = new PrintStream(err, true, "UTF-8");
        assertEquals(SecretStore.EXIT_FAILURE, SecretStore.run(o, e, "store=" + file, "store.password=" + new String(shortPW), "command=create"));
        assertTrue(err.toString("UTF-8").contains("at least " + SecretStore.MIN_PASSWORD_LENGTH), err.toString("UTF-8"));
        assertEquals(SecretStore.EXIT_FAILURE, SecretStore.run(o, e, "store=" + file, "store.password=" + new String(PW), "command=create", "kdf=md5"));
        assertFalse(file.exists(), "nothing is written");
        assertEquals(SecretStore.EXIT_OK, SecretStore.run(o, e, "store=" + file, "store.password=" + new String(PW), "command=create", "kdf=pbkdf2"), err.toString("UTF-8"));
        assertEquals(PBKDF2, SecretStore.describeKDF(file));
    }

    @Test
    public void save_posixPermissions_ownerOnlyWhenNew_keptWhenExisting(@TempDir Path dir) throws Exception {
        Assumptions.assumeTrue(dir.getFileSystem().supportedFileAttributeViews().contains("posix"), "POSIX file systems only");
        File file = dir.resolve("vault.bcfks").toFile();
        try (SecretStore ss = SecretStore.create(file, PW)) {
            ss.put("k", "v");
            ss.save();
        }
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file.toPath())));
        Files.setPosixFilePermissions(file.toPath(), PosixFilePermissions.fromString("rw-r-----"));
        try (SecretStore ss = SecretStore.open(file, PW)) {
            ss.put("k", "v2");
            ss.save();
        }
        assertEquals("rw-r-----", PosixFilePermissions.toString(Files.getPosixFilePermissions(file.toPath())), "an operator's choice is kept");
    }

    @Test
    public void storeParam_namesAndMandatoryFlags_missingMandatory() throws Exception {
        assertEquals("master-key", SecretStore.StoreParam.MASTER_KEY.getName());
        assertEquals(SecretStore.SUPER_ADMIN_ID, SecretStore.StoreParam.SUPER_ADMIN_ID.getName());
        assertEquals("super-admin-password", SecretStore.StoreParam.SUPER_ADMIN_PASSWORD.getName());
        assertEquals("db.url", SecretStore.StoreParam.DB_URL.getName());
        assertEquals("db.user", SecretStore.StoreParam.DB_USER.getName());
        assertEquals("db.password", SecretStore.StoreParam.DB_PASSWORD.getName());
        assertEquals("db.enc-password", SecretStore.StoreParam.DB_ENC_PASSWORD.getName());
        for (SecretStore.StoreParam param : SecretStore.StoreParam.values()) {
            boolean expected = param == SecretStore.StoreParam.MASTER_KEY
                    || param == SecretStore.StoreParam.SUPER_ADMIN_ID
                    || param == SecretStore.StoreParam.SUPER_ADMIN_PASSWORD
                    || param == SecretStore.StoreParam.DB_URL;
            assertEquals(expected, param.isMandatory(), param.getName());
        }

        try (SecretStore ss = SecretStore.inMemory(PW.clone())) {
            assertEquals(Arrays.asList(SecretStore.StoreParam.MASTER_KEY, SecretStore.StoreParam.SUPER_ADMIN_ID,
                    SecretStore.StoreParam.SUPER_ADMIN_PASSWORD, SecretStore.StoreParam.DB_URL), ss.missingMandatory(),
                    "an empty store lacks all four");
            ss.put(SecretStore.StoreParam.DB_USER.getName(), "dbuser");
            assertEquals(4, ss.missingMandatory().size(), "an optional entry changes nothing");
            ss.createSecretKey(SecretStore.StoreParam.MASTER_KEY.getName());
            ss.setSuperAdminID("admin.local");
            ss.put(SecretStore.StoreParam.SUPER_ADMIN_PASSWORD.getName(), "Init-1234-aA1!");
            assertEquals(Arrays.asList(SecretStore.StoreParam.DB_URL), ss.missingMandatory());
            ss.put(SecretStore.StoreParam.DB_URL.getName(), "jdbc:h2:mem:x");
            assertTrue(ss.missingMandatory().isEmpty(), "complete");
        }
    }

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
    public void superAdminID_setUpdateRemove(@TempDir Path dir) throws Exception {
        File file = dir.resolve("vault.bcfks").toFile();
        try (SecretStore ss = SecretStore.create(file, PW)) {
            assertNull(ss.getSuperAdminID());
            assertFalse(ss.removeSuperAdminID());
            ss.setSuperAdminID("  Root@XLogistX.io ");
            assertEquals("root@xlogistx.io", ss.getSuperAdminID(), "email is trimmed and lower-cased");
            ss.save();
        }
        try (SecretStore ss = SecretStore.open(file, PW)) {
            assertEquals("root@xlogistx.io", ss.getSuperAdminID());
            assertEquals(SecretStore.EntryType.TEXT, ss.typeOf(SecretStore.SUPER_ADMIN_ID));
            assertEquals("root@xlogistx.io", ss.toNVGenericMap().getValue(SecretStore.SUPER_ADMIN_ID));

            // update: a username replaces the email
            ss.setSuperAdminID("SuperAdmin");
            assertEquals("superadmin", ss.getSuperAdminID());
            assertEquals(1, ss.size());

            // neither an email nor a username: rejected, previous value kept
            assertThrows(IllegalArgumentException.class, () -> ss.setSuperAdminID("super admin"));
            assertThrows(IllegalArgumentException.class, () -> ss.setSuperAdminID("root"));
            assertThrows(NullPointerException.class, () -> ss.setSuperAdminID("   "));
            assertThrows(IllegalArgumentException.class, () -> ss.put(SecretStore.SUPER_ADMIN_ID, "bad id@"), "put validates too");
            assertEquals("superadmin", ss.getSuperAdminID());
            ss.save();
        }
        try (SecretStore ss = SecretStore.open(file, PW)) {
            assertEquals("superadmin", ss.getSuperAdminID());
            assertTrue(ss.removeSuperAdminID());
            assertNull(ss.getSuperAdminID());
            ss.save();
        }
        try (SecretStore ss = SecretStore.open(file, PW)) {
            assertNull(ss.getSuperAdminID());
            assertEquals(0, ss.size());
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

        // super admin id: set, update, reject, delete
        String adminName = "name=" + SecretStore.SUPER_ADMIN_ID;
        assertEquals(SecretStore.EXIT_OK, SecretStore.run(o, e, "store=" + store, pw, "command=put", adminName, "value=superadmin"), err.toString());
        assertEquals(SecretStore.EXIT_OK, SecretStore.run(o, e, "store=" + store, pw, "command=put", adminName, "value=Root@XLogistX.io"), err.toString());
        assertEquals(SecretStore.EXIT_FAILURE, SecretStore.run(o, e, "store=" + store, pw, "command=put", adminName, "value=root"), "too short for a username");
        out.reset();
        assertEquals(SecretStore.EXIT_OK, SecretStore.run(o, e, "store=" + store, pw, "command=get", adminName));
        assertEquals("root@xlogistx.io", out.toString("UTF-8").trim());
        assertEquals(SecretStore.EXIT_OK, SecretStore.run(o, e, "store=" + store, pw, "command=remove", adminName));
        assertEquals(SecretStore.EXIT_FAILURE, SecretStore.run(o, e, "store=" + store, pw, "command=get", adminName), "deleted");

        try (SecretStore ss = SecretStore.open(new File(store), PW)) {
            assertEquals(Arrays.asList("db.password", "db.user", "kem", "signer"), new java.util.ArrayList<>(ss.aliases()));
            assertEquals(2, ss.toNVGenericMap().size());
            PrivateKey kem = ss.getPrivateKey("kem");
            assertEquals(SecretStore.DEFAULT_ML_KEM, kem.getAlgorithm());
            assertEquals(2, ss.getCertificateChain("kem").length);
        }
    }
}
