package io.xlogistx.opsec;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.SecUtil;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.util.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.PBEKey;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * A password-protected store for application secrets and keys, so that a server needs one
 * password at start-up and loads everything else from the store: text secrets such as
 * {@code db.url}, {@code db.user}, {@code db.password}, plus symmetric keys (for example the
 * KeyMakerProvider master key) and post-quantum key pairs (ML-DSA for signing, ML-KEM for key
 * encapsulation).
 * <p>
 * The file is a Bouncy Castle {@code BCFKS} keystore (PBKDF2 key derivation, AES-CCM entry
 * protection, HMAC-SHA512 integrity), the only keystore type on this stack that holds text
 * secrets, symmetric keys and ML-DSA/ML-KEM private keys in one file: the JDK and BC PKCS12
 * implementations refuse the secret-entry shapes this provider order produces. A wrong password
 * fails the integrity check ({@link IOException}). One password covers the store and every entry.
 * <p>
 * Entry types, all sharing one alias namespace:
 * <ul>
 *   <li>{@link EntryType#TEXT}: a text secret, stored as a BCFKS password entry ({@link PBEKey});
 *       {@link #toNVGenericMap()} returns exactly these, as {@code name -> value}, ready to feed
 *       application configuration.</li>
 *   <li>{@link EntryType#SECRET_KEY}: a symmetric key ({@link #createSecretKey}).</li>
 *   <li>{@link EntryType#KEY_PAIR}: a private key with its certificate chain. ML-DSA keys get a
 *       self-signed certificate; ML-KEM keys cannot sign, so their certificate is issued by an
 *       ML-DSA signer from this store ({@code signerAlias}) or, when none is named, by an
 *       ephemeral ML-DSA-65 key that is discarded Afterwards (the certificate is then only a
 *       container for the public key).</li>
 * </ul>
 * Key material is generated and reloaded through the BC provider, so reloaded keys work
 * directly with {@link OPSecUtil}'s KEM helpers and BC {@link Signature}.
 * <p>
 * Command line ({@code key=value} arguments; {@code store.password} and {@code value} are hidden
 * from logs; a missing password or value is prompted on the console):
 * <pre>
 *   store=&lt;file&gt; store.password=&lt;pw&gt; command=create
 *   store=... store.password=... command=put name=db.password [value=&lt;secret&gt;]
 *   store=... store.password=... command=get name=db.password
 *   store=... store.password=... command=list
 *   store=... store.password=... command=remove name=&lt;alias&gt;
 *   store=... store.password=... command=ml-dsa alias=&lt;alias&gt; [algo=ML-DSA-44|ML-DSA-65|ML-DSA-87] [subject=CN=...] [validity=10year]
 *   store=... store.password=... command=ml-kem alias=&lt;alias&gt; [algo=ML-KEM-512|ML-KEM-768|ML-KEM-1024] [signer=&lt;ml-dsa alias&gt;] [subject=CN=...] [validity=10year]
 *   store=... store.password=... command=secret-key alias=&lt;alias&gt; [algo=AES] [bits=256]
 * </pre>
 */
public final class SecretStore implements AutoCloseable {

    private static final LogWrapper log = new LogWrapper(SecretStore.class).setEnabled(false);

    /**
     * BCFKS: the one keystore type here that stores text secrets, symmetric keys and ML-DSA/ML-KEM private keys (see class javadoc).
     */
    public static final String TYPE = CryptoConst.KSType.BCFKS.getName();
    public static final String PROVIDER = SecUtil.BC_PROVIDER;
    public static final String DEFAULT_VALIDITY = "10year";
    public static final String DEFAULT_SUBJECT_PREFIX = "CN=";

    public static final String DEFAULT_ML_DSA = CryptoConst.ML_DSA_65;
    public static final String DEFAULT_ML_KEM = CryptoConst.ML_KEM_768;
    public static final CollectionAsArray<String> ML_DSA_ALGORITHMS = new CollectionAsArray<>(new ArrayList<>(), new String[0]).add(CryptoConst.ML_DSA_44, CryptoConst.ML_DSA_65, CryptoConst.ML_DSA_87);
    public static final CollectionAsArray<String> ML_KEM_ALGORITHMS = new CollectionAsArray<>(new ArrayList<>(), new String[0]).add(CryptoConst.ML_KEM_512, CryptoConst.ML_KEM_768, CryptoConst.ML_KEM_1024);

    public enum EntryType {
        /**
         * Text secret; part of {@link #toNVGenericMap()}.
         */
        TEXT,
        /**
         * Symmetric key.
         */
        SECRET_KEY,
        /**
         * Private key + certificate chain.
         */
        KEY_PAIR,
        /**
         * Trusted certificate only.
         */
        CERTIFICATE,
        /**
         * No such alias.
         */
        NONE
    }

    /**
     * The shape BCFKS stores as a password entry; the characters come back via {@link PBEKey#getPassword()}.
     */
    private static final class TextSecret implements PBEKey {
        private final char[] value;

        TextSecret(char[] value) {
            this.value = value;
        }

        @Override
        public char[] getPassword() {
            return value.clone();
        }

        @Override
        public byte[] getSalt() {
            return null;
        }

        @Override
        public int getIterationCount() {
            return 0;
        }

        @Override
        public String getAlgorithm() {
            return "PBE";
        }

        @Override
        public String getFormat() {
            return "RAW";
        }

        @Override
        public byte[] getEncoded() {
            return new String(value).getBytes(StandardCharsets.UTF_8);
        }
    }

    private final KeyStore keyStore;
    private final char[] password;
    private final File file;
    private final KeyStore.PasswordProtection protection;

    private SecretStore(KeyStore keyStore, char[] password, File file) {
        this.keyStore = keyStore;
        this.password = password;
        this.file = file;
        this.protection = new KeyStore.PasswordProtection(password);
    }

    // ------------------------------------------------------------------
    // Open / create / save
    // ------------------------------------------------------------------

    /**
     * A new empty store bound to {@code file}, written immediately; fails if the file exists.
     */
    public static SecretStore create(File file, char[] password) throws IOException, GeneralSecurityException {
        SUS.checkIfNulls("file and password can't be null", file, password);
        if (file.exists()) {
            throw new IOException("secret store already exists: " + file);
        }
        SecretStore ret = new SecretStore(emptyKeyStore(password), password.clone(), file);
        ret.save();
        return ret;
    }

    /**
     * Loads an existing store; a wrong password fails the integrity check with an {@link IOException}.
     */
    public static SecretStore open(File file, char[] password) throws IOException, GeneralSecurityException {
        SUS.checkIfNulls("file and password can't be null", file, password);
        if (!file.isFile()) {
            throw new FileNotFoundException("secret store not found: " + file);
        }
        try (InputStream is = Files.newInputStream(file.toPath())) {
            return new SecretStore(loadKeyStore(is, password), password.clone(), file);
        }
    }

    /**
     * {@link #open} when the file exists, else {@link #create}.
     */
    public static SecretStore openOrCreate(File file, char[] password) throws IOException, GeneralSecurityException {
        return file.exists() ? open(file, password) : create(file, password);
    }

    /**
     * Loads from a stream; {@link #save()} needs {@link #save(OutputStream)} since there is no file.
     */
    public static SecretStore load(InputStream is, char[] password) throws IOException, GeneralSecurityException {
        SUS.checkIfNulls("stream and password can't be null", is, password);
        return new SecretStore(loadKeyStore(is, password), password.clone(), null);
    }

    /**
     * An empty in-memory store (tests, or building a store to write with {@link #save(OutputStream)}).
     */
    public static SecretStore inMemory(char[] password) throws IOException, GeneralSecurityException {
        SUS.checkIfNulls("password can't be null", password);
        return new SecretStore(emptyKeyStore(password), password.clone(), null);
    }

    private static KeyStore emptyKeyStore(char[] password) throws IOException, GeneralSecurityException {
        OPSecUtil.singleton();
        KeyStore ks = KeyStore.getInstance(TYPE, PROVIDER);
        ks.load(null, password);
        return ks;
    }

    private static KeyStore loadKeyStore(InputStream is, char[] password) throws IOException, GeneralSecurityException {
        OPSecUtil.singleton();
        KeyStore ks = KeyStore.getInstance(TYPE, PROVIDER);
        ks.load(is, password);
        return ks;
    }

    /**
     * Writes the store to its file (atomically: temp file + move).
     */
    public void save() throws IOException, GeneralSecurityException {
        if (file == null) {
            throw new IllegalStateException("store is not bound to a file: use save(OutputStream)");
        }
        File parent = file.getAbsoluteFile().getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IOException("cannot create directory " + parent);
        }
        File tmp = new File(parent, file.getName() + ".tmp");
        try (OutputStream os = Files.newOutputStream(tmp.toPath())) {
            keyStore.store(os, password);
        }
        Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    public void save(OutputStream os) throws IOException, GeneralSecurityException {
        SUS.checkIfNulls("stream can't be null", os);
        keyStore.store(os, password);
    }

    public File getFile() {
        return file;
    }

    /**
     * The underlying keystore, e.g. for {@code KeyMakerProvider.setMasterKey(keystore, alias, password)}.
     */
    public KeyStore getKeyStore() {
        return keyStore;
    }

    /**
     * Zeroes the in-memory copy of the password; the store object must not be used afterwards.
     */
    @Override
    public void close() {
        Arrays.fill(password, '\0');
        try {
            protection.destroy();
        } catch (Exception ignore) {
            // best effort
        }
    }

    // ------------------------------------------------------------------
    // Text secrets
    // ------------------------------------------------------------------

    /**
     * Stores (or replaces) a text secret under {@code name}. Not saved until {@link #save()}.
     */
    public SecretStore put(String name, String value) throws GeneralSecurityException {
        name = checkAlias(name);
        SUS.checkIfNulls("value can't be null", value);
        keyStore.setEntry(name, new KeyStore.SecretKeyEntry(new TextSecret(value.toCharArray())), protection);
        return this;
    }

    /**
     * Stores every value of the map as a text secret ({@code String.valueOf} of the value).
     */
    public SecretStore putAll(NVGenericMap values) throws GeneralSecurityException {
        SUS.checkIfNulls("values can't be null", values);
        for (GetNameValue<?> nv : values.values()) {
            Object v = nv.getValue();
            if (v != null) {
                put(nv.getName(), String.valueOf(v));
            }
        }
        return this;
    }

    /**
     * The text secret under {@code name}, or null when absent or not a text entry.
     */
    public String get(String name) throws GeneralSecurityException {
        Key key = key(name);
        if (key instanceof PBEKey) {
            char[] chars = ((PBEKey) key).getPassword();
            try {
                return new String(chars);
            } finally {
                Arrays.fill(chars, '\0');
            }
        }
        return null;
    }

    public String get(String name, String defaultValue) throws GeneralSecurityException {
        String ret = get(name);
        return ret != null ? ret : defaultValue;
    }

    /**
     * Every text secret as {@code name -> value}, in alias order. Keys and certificates are left out.
     */
    public NVGenericMap toNVGenericMap() throws GeneralSecurityException {
        return toNVGenericMap(null);
    }

    /**
     * Text secrets whose name starts with {@code prefix} (null or empty = all), e.g. {@code "db."}
     * to load only the datastore settings. Names are kept as stored (the prefix is not stripped).
     */
    public NVGenericMap toNVGenericMap(String prefix) throws GeneralSecurityException {
        NVGenericMap ret = new NVGenericMap();
        for (String alias : aliases()) {
            if (!SUS.isEmpty(prefix) && !alias.startsWith(prefix)) {
                continue;
            }
            String value = get(alias);
            if (value != null) {
                ret.add(alias, value);
            }
        }
        return ret;
    }

    // ------------------------------------------------------------------
    // Keys
    // ------------------------------------------------------------------

    /**
     * Generates a symmetric key ({@code AES} by default) and stores it under {@code alias}.
     */
    public SecretKey createSecretKey(String alias, String algorithm, int bits) throws GeneralSecurityException {
        alias = checkAlias(alias);
        if (SUS.isEmpty(algorithm)) {
            algorithm = CryptoConst.CryptoAlgo.AES.getName();
        }
        KeyGenerator kg = KeyGenerator.getInstance(algorithm);
        kg.init(bits, SecUtil.defaultSecureRandom());
        SecretKey key = kg.generateKey();
        keyStore.setEntry(alias, new KeyStore.SecretKeyEntry(key), protection);
        return key;
    }

    public SecretKey createSecretKey(String alias) throws GeneralSecurityException {
        return createSecretKey(alias, null, CryptoConst.AES_256_KEY_SIZE * 8);
    }

    /**
     * Stores an existing symmetric key.
     */
    public SecretStore putSecretKey(String alias, SecretKey key) throws GeneralSecurityException {
        alias = checkAlias(alias);
        SUS.checkIfNulls("key can't be null", key);
        keyStore.setEntry(alias, new KeyStore.SecretKeyEntry(key), protection);
        return this;
    }

    /**
     * The symmetric key under {@code alias}, or null when absent or a different entry type.
     */
    public SecretKey getSecretKey(String alias) throws GeneralSecurityException {
        Key key = key(alias);
        return key instanceof SecretKey && !(key instanceof PBEKey) ? (SecretKey) key : null;
    }

    /**
     * ML-DSA-65 key pair with a self-signed certificate ({@code CN=<alias>}, {@value #DEFAULT_VALIDITY}).
     */
    public KeyPair createMLDSA(String alias) throws GeneralSecurityException, IOException {
        return createMLDSA(alias, DEFAULT_ML_DSA, null, null);
    }

    /**
     * Generates an ML-DSA signing key pair and stores it with a self-signed certificate.
     *
     * @param alias     entry name
     * @param algorithm {@code ML-DSA-44}, {@code ML-DSA-65} (default) or {@code ML-DSA-87}
     * @param subject   X.500 subject, default {@code CN=<alias>}
     * @param validity  certificate lifetime in {@link Const.TimeInMillis} syntax, default {@value #DEFAULT_VALIDITY}
     */
    public KeyPair createMLDSA(String alias, String algorithm, String subject, String validity)
            throws GeneralSecurityException, IOException {
        alias = checkAlias(alias);
        algorithm = checkAlgorithm(algorithm, DEFAULT_ML_DSA, ML_DSA_ALGORITHMS, "ML-DSA");
        KeyPair kp = generate(algorithm);
        X509Certificate cert = certificate(kp.getPublic(), subjectOf(subject, alias), kp.getPrivate(), algorithm,
                subjectOf(subject, alias), validity);
        keyStore.setKeyEntry(alias, kp.getPrivate(), password, new Certificate[]{cert});
        return kp;
    }

    /**
     * ML-KEM-768 key pair; its certificate is issued by an ephemeral ML-DSA-65 key.
     */
    public KeyPair createMLKEM(String alias) throws GeneralSecurityException, IOException {
        return createMLKEM(alias, DEFAULT_ML_KEM, null, null, null);
    }

    /**
     * Generates an ML-KEM key-encapsulation key pair and stores it with a certificate.
     *
     * @param alias       entry name
     * @param algorithm   {@code ML-KEM-512}, {@code ML-KEM-768} (default) or {@code ML-KEM-1024}
     * @param signerAlias an ML-DSA {@link EntryType#KEY_PAIR} of this store that issues the
     *                    certificate (chain = [kem, signer]); null = ephemeral ML-DSA-65 issuer,
     *                    the certificate then only carries the public key
     * @param subject     X.500 subject, default {@code CN=<alias>}
     * @param validity    certificate lifetime, default {@value #DEFAULT_VALIDITY}
     */
    public KeyPair createMLKEM(String alias, String algorithm, String signerAlias, String subject, String validity)
            throws GeneralSecurityException, IOException {
        alias = checkAlias(alias);
        algorithm = checkAlgorithm(algorithm, DEFAULT_ML_KEM, ML_KEM_ALGORITHMS, "ML-KEM");
        KeyPair kp = generate(algorithm);
        X500Name subjectName = subjectOf(subject, alias);
        PrivateKey signerKey;
        String signerAlgorithm;
        X500Name issuer;
        List<Certificate> chain = new ArrayList<>();
        if (SUS.isEmpty(signerAlias)) {
            KeyPair ephemeral = generate(DEFAULT_ML_DSA);
            signerKey = ephemeral.getPrivate();
            signerAlgorithm = DEFAULT_ML_DSA;
            issuer = subjectName;
        } else {
            X509Certificate signerCert = getCertificate(signerAlias);
            PrivateKey key = getPrivateKey(signerAlias);
            if (signerCert == null || key == null || !ML_DSA_ALGORITHMS.contains(key.getAlgorithm())) {
                throw new IllegalArgumentException("signer must be an ML-DSA key pair of this store: " + signerAlias);
            }
            signerKey = key;
            signerAlgorithm = key.getAlgorithm();
            issuer = X500Name.getInstance(signerCert.getSubjectX500Principal().getEncoded());
            chain.add(signerCert);
        }
        X509Certificate cert = certificate(kp.getPublic(), subjectName, signerKey, signerAlgorithm, issuer, validity);
        chain.add(0, cert);
        keyStore.setKeyEntry(alias, kp.getPrivate(), password, chain.toArray(new Certificate[0]));
        return kp;
    }

    /**
     * Stores an existing private key with its chain (any algorithm the BC provider encodes).
     */
    public SecretStore putKeyPair(String alias, PrivateKey key, Certificate... chain) throws GeneralSecurityException {
        alias = checkAlias(alias);
        SUS.checkIfNulls("key can't be null", key);
        if (chain == null || chain.length == 0) {
            throw new IllegalArgumentException("a private key needs its certificate chain");
        }
        keyStore.setKeyEntry(alias, key, password, chain);
        return this;
    }

    public PrivateKey getPrivateKey(String alias) throws GeneralSecurityException {
        Key key = key(alias);
        return key instanceof PrivateKey ? (PrivateKey) key : null;
    }

    public PublicKey getPublicKey(String alias) throws GeneralSecurityException {
        X509Certificate cert = getCertificate(alias);
        return cert != null ? cert.getPublicKey() : null;
    }

    /**
     * Private + public key of a {@link EntryType#KEY_PAIR} entry, or null.
     */
    public KeyPair getKeyPair(String alias) throws GeneralSecurityException {
        PrivateKey priv = getPrivateKey(alias);
        PublicKey pub = getPublicKey(alias);
        return priv != null && pub != null ? new KeyPair(pub, priv) : null;
    }

    public X509Certificate getCertificate(String alias) throws GeneralSecurityException {
        if (SUS.isEmpty(alias)) {
            return null;
        }
        Certificate cert = keyStore.getCertificate(alias.trim());
        return cert instanceof X509Certificate ? (X509Certificate) cert : null;
    }

    public Certificate[] getCertificateChain(String alias) throws GeneralSecurityException {
        return SUS.isEmpty(alias) ? null : keyStore.getCertificateChain(alias.trim());
    }

    // ------------------------------------------------------------------
    // Inventory
    // ------------------------------------------------------------------

    /**
     * Removes any entry; true if it existed. Not saved until {@link #save()}.
     */
    public boolean remove(String alias) throws GeneralSecurityException {
        if (SUS.isEmpty(alias) || !keyStore.containsAlias(alias.trim())) {
            return false;
        }
        keyStore.deleteEntry(alias.trim());
        return true;
    }

    public boolean contains(String alias) throws GeneralSecurityException {
        return !SUS.isEmpty(alias) && keyStore.containsAlias(alias.trim());
    }

    /**
     * All aliases, sorted.
     */
    public SortedSet<String> aliases() throws GeneralSecurityException {
        return new TreeSet<>(Collections.list(keyStore.aliases()));
    }

    public EntryType typeOf(String alias) throws GeneralSecurityException {
        if (!contains(alias)) {
            return EntryType.NONE;
        }
        alias = alias.trim();
        if (keyStore.isCertificateEntry(alias)) {
            return EntryType.CERTIFICATE;
        }
        Key key = keyStore.getKey(alias, password);
        if (key instanceof PBEKey) {
            return EntryType.TEXT;
        }
        if (key instanceof PrivateKey) {
            return EntryType.KEY_PAIR;
        }
        if (key instanceof SecretKey) {
            return EntryType.SECRET_KEY;
        }
        return EntryType.NONE;
    }

    public int size() throws GeneralSecurityException {
        return keyStore.size();
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    private Key key(String alias) throws GeneralSecurityException {
        if (SUS.isEmpty(alias)) {
            return null;
        }
        alias = alias.trim();
        return keyStore.containsAlias(alias) ? keyStore.getKey(alias, password) : null;
    }

    private static String checkAlias(String alias) {
        if (SUS.isEmpty(alias) || alias.trim().isEmpty()) {
            throw new IllegalArgumentException("alias/name can't be empty");
        }
        return alias.trim();
    }

    private static String checkAlgorithm(String algorithm, String defaultAlgorithm, CollectionAsArray<String> allowed, String family) {
        if (SUS.isEmpty(algorithm)) {
            return defaultAlgorithm;
        }

        if (!allowed.contains(algorithm, RefMatcher.TrimIgnoreCase)) {
            throw new IllegalArgumentException(family + " algorithm must be one of " + Arrays.toString(allowed.asArray()) + ": " + algorithm);
        }

        return algorithm.trim().toUpperCase();
    }

    private static KeyPair generate(String algorithm) throws GeneralSecurityException {
        return KeyPairGenerator.getInstance(algorithm, PROVIDER).generateKeyPair();
    }

    private static X500Name subjectOf(String subject, String alias) {
        return new X500Name(SUS.isEmpty(subject) ? DEFAULT_SUBJECT_PREFIX + alias : subject.trim());
    }

    private static X509Certificate certificate(PublicKey subjectKey, X500Name subject, PrivateKey signerKey,
                                               String signerAlgorithm, X500Name issuer, String validity)
            throws GeneralSecurityException, IOException {
        long millis = Const.TimeInMillis.toMillis(SUS.isEmpty(validity) ? DEFAULT_VALIDITY : validity);
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + millis);
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer,
                new BigInteger(64, SecUtil.defaultSecureRandom()), notBefore, notAfter, subject, subjectKey);
        try {
            ContentSigner signer = new JcaContentSignerBuilder(signerAlgorithm).setProvider(PROVIDER).build(signerKey);
            return new JcaX509CertificateConverter().setProvider(PROVIDER).getCertificate(builder.build(signer));
        } catch (OperatorCreationException e) {
            throw new CertificateException("cannot sign certificate with " + signerAlgorithm, e);
        }
    }

    // ------------------------------------------------------------------
    // Command line
    // ------------------------------------------------------------------

    public enum Command implements GetName {
        CREATE("create"),
        PUT("put"),
        GET("get"),
        LIST("list"),
        REMOVE("remove"),
        ML_DSA("ml-dsa"),
        ML_KEM("ml-kem"),
        SECRET_KEY("secret-key"),
        ;
        private final String name;

        Command(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }
    }

    public enum Param implements GetName {
        STORE("store"),
        STORE_PASSWORD("store.password"),
        COMMAND("command"),
        NAME("name"),
        VALUE("value"),
        ALIAS("alias"),
        ALGO("algo"),
        BITS("bits"),
        SIGNER("signer"),
        SUBJECT("subject"),
        VALIDITY("validity"),
        ;
        private final String name;

        Param(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }
    }

    public static final String USAGE =
            "Usage: store=<file> store.password=<pw or console prompt> command=<command> [options]\n"
                    + "\n"
                    + "Commands:\n"
                    + "  create                       new empty store (fails if the file exists)\n"
                    + "  put        name=<n> [value=<v>]           store a text secret (value prompted when absent)\n"
                    + "  get        name=<n>                       print a text secret\n"
                    + "  list                                      aliases and their types, never values\n"
                    + "  remove     name=<alias>                   delete any entry\n"
                    + "  ml-dsa     alias=<a> [algo=" + CryptoConst.ML_DSA_44 + "|" + CryptoConst.ML_DSA_65 + "|" + CryptoConst.ML_DSA_87 + "] [subject=CN=..] [validity=" + DEFAULT_VALIDITY + "]\n"
                    + "  ml-kem     alias=<a> [algo=" + CryptoConst.ML_KEM_512 + "|" + CryptoConst.ML_KEM_768 + "|" + CryptoConst.ML_KEM_1024 + "] [signer=<ml-dsa alias>] [subject=CN=..] [validity=" + DEFAULT_VALIDITY + "]\n"
                    + "  secret-key alias=<a> [algo=AES] [bits=256]\n"
                    + "\n"
                    + "The store is a " + TYPE + " keystore; one password protects the file and every entry.";

    public static final int EXIT_OK = 0;
    public static final int EXIT_USAGE = 1;
    public static final int EXIT_FAILURE = 2;

    public static void main(String... args) {
        System.exit(run(System.out, System.err, args));
    }

    /**
     * In-process entry point; returns the exit code instead of exiting.
     */
    public static int run(PrintStream out, PrintStream err, String... args) {
        ParamUtil.ParamMap params;
        Command command;
        File storeFile;
        try {
            params = ParamUtil.parse("=", args);
            params.hide(Param.STORE_PASSWORD, Param.VALUE);
            command = params.enumValue(Param.COMMAND, Command.values());
            if (command == null) {
                throw new IllegalArgumentException("command is missing or unknown");
            }
            String store = params.stringValue(Param.STORE, null);
            if (SUS.isEmpty(store)) {
                throw new IllegalArgumentException("store=<file> is required");
            }
            storeFile = new File(store.trim());
        } catch (RuntimeException e) {
            err.println(e.getMessage());
            err.println(USAGE);
            return EXIT_USAGE;
        }

        char[] storePassword = readSecret(params.stringValue(Param.STORE_PASSWORD, null), "Store password: ",
                command == Command.CREATE, err);
        if (storePassword == null) {
            return EXIT_USAGE;
        }
        try (SecretStore ss = command == Command.CREATE ? create(storeFile, storePassword) : open(storeFile, storePassword)) {
            switch (command) {
                case CREATE:
                    out.println("created " + storeFile + " (" + TYPE + ")");
                    return EXIT_OK;
                case PUT: {
                    String name = params.stringValue(Param.NAME, null);
                    if (SUS.isEmpty(name)) {
                        err.println("put needs name=<name>");
                        return EXIT_USAGE;
                    }
                    char[] value = readSecret(params.stringValue(Param.VALUE, null), "Value for " + name + ": ", true, err);
                    if (value == null) {
                        return EXIT_USAGE;
                    }
                    boolean replaced = ss.contains(name);
                    ss.put(name, new String(value));
                    Arrays.fill(value, '\0');
                    ss.save();
                    out.println((replaced ? "replaced " : "stored ") + name.trim());
                    return EXIT_OK;
                }
                case GET: {
                    String name = params.stringValue(Param.NAME, null);
                    if (SUS.isEmpty(name)) {
                        err.println("get needs name=<name>");
                        return EXIT_USAGE;
                    }
                    String value = ss.get(name);
                    if (value == null) {
                        err.println("no text secret named " + name.trim() + " (" + ss.typeOf(name) + ")");
                        return EXIT_FAILURE;
                    }
                    out.println(value);
                    return EXIT_OK;
                }
                case LIST: {
                    for (String alias : ss.aliases()) {
                        EntryType type = ss.typeOf(alias);
                        String detail = "";
                        if (type == EntryType.KEY_PAIR) {
                            PrivateKey pk = ss.getPrivateKey(alias);
                            X509Certificate cert = ss.getCertificate(alias);
                            detail = "  " + pk.getAlgorithm() + (cert != null ? " " + cert.getSubjectX500Principal().getName()
                                    + " until " + cert.getNotAfter() : "");
                        } else if (type == EntryType.SECRET_KEY) {
                            SecretKey sk = ss.getSecretKey(alias);
                            detail = "  " + sk.getAlgorithm() + (sk.getEncoded() != null ? " " + sk.getEncoded().length * 8 + " bits" : "");
                        }
                        out.println(alias + "  " + type + detail);
                    }
                    out.println(ss.size() + " entries");
                    return EXIT_OK;
                }
                case REMOVE: {
                    String name = params.stringValue(Param.NAME, null);
                    if (SUS.isEmpty(name)) {
                        err.println("remove needs name=<alias>");
                        return EXIT_USAGE;
                    }
                    if (!ss.remove(name)) {
                        err.println("no entry named " + name.trim());
                        return EXIT_FAILURE;
                    }
                    ss.save();
                    out.println("removed " + name.trim());
                    return EXIT_OK;
                }
                case ML_DSA: {
                    String alias = params.stringValue(Param.ALIAS, null);
                    if (SUS.isEmpty(alias)) {
                        err.println("ml-dsa needs alias=<alias>");
                        return EXIT_USAGE;
                    }
                    ss.createMLDSA(alias, params.stringValue(Param.ALGO, null), params.stringValue(Param.SUBJECT, null),
                            params.stringValue(Param.VALIDITY, null));
                    ss.save();
                    out.println("created " + ss.getPrivateKey(alias).getAlgorithm() + " key pair " + alias.trim());
                    return EXIT_OK;
                }
                case ML_KEM: {
                    String alias = params.stringValue(Param.ALIAS, null);
                    if (SUS.isEmpty(alias)) {
                        err.println("ml-kem needs alias=<alias>");
                        return EXIT_USAGE;
                    }
                    ss.createMLKEM(alias, params.stringValue(Param.ALGO, null), params.stringValue(Param.SIGNER, null),
                            params.stringValue(Param.SUBJECT, null), params.stringValue(Param.VALIDITY, null));
                    ss.save();
                    out.println("created " + ss.getPrivateKey(alias).getAlgorithm() + " key pair " + alias.trim());
                    return EXIT_OK;
                }
                case SECRET_KEY: {
                    String alias = params.stringValue(Param.ALIAS, null);
                    if (SUS.isEmpty(alias)) {
                        err.println("secret-key needs alias=<alias>");
                        return EXIT_USAGE;
                    }
                    int bits = params.intValue(Param.BITS.getName(), CryptoConst.AES_256_KEY_SIZE * 8);
                    SecretKey key = ss.createSecretKey(alias, params.stringValue(Param.ALGO, null), bits);
                    ss.save();
                    out.println("created " + key.getAlgorithm() + " " + bits + "-bit key " + alias.trim());
                    return EXIT_OK;
                }
                default:
                    err.println(USAGE);
                    return EXIT_USAGE;
            }
        } catch (Exception e) {
            err.println(command.getName() + " failed: " + e.getMessage());
            log.getLogger().severe(command.getName() + " failed: " + e);
            return EXIT_FAILURE;
        } finally {
            Arrays.fill(storePassword, '\0');
        }
    }

    /**
     * The given value, else a console prompt (repeated when {@code confirm}), else null after an
     * error on {@code err}.
     */
    private static char[] readSecret(String given, String prompt, boolean confirm, PrintStream err) {
        if (!SUS.isEmpty(given)) {
            return given.toCharArray();
        }
        Console console = System.console();
        if (console == null) {
            err.println("value required: pass it as an argument or run from an interactive console");
            return null;
        }
        char[] first = console.readPassword(prompt);
        if (first == null || first.length == 0) {
            err.println("empty value");
            return null;
        }
        if (confirm) {
            char[] second = console.readPassword("Repeat: ");
            boolean same = Arrays.equals(first, second);
            if (second != null) Arrays.fill(second, '\0');
            if (!same) {
                Arrays.fill(first, '\0');
                err.println("values do not match");
                return null;
            }
        }
        return first;
    }
}
