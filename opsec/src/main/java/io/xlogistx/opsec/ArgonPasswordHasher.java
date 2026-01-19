package io.xlogistx.opsec;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.PasswordHasher;
import org.zoxweb.server.security.SecUtil;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.util.*;

import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ArgonPasswordHasher extends PasswordHasher {

    public static final LogWrapper log = new LogWrapper(ArgonPasswordHasher.class).setEnabled(true);
    public enum Argon2
            implements GetName {
//        ALGORITHM("algorithm", -1),
        MEMORY("m", Const.SizeInBytes.K.mult(15)),
        SALT_LEN("salt_len", 32),
        HASH_LEN("hash_len", 32),
        ROUNDS("t", 3),
        PARALLELISM("p", 2),
//        HASH("hash", -1),
//        SALT("halt", -1),
        VERSION("version", 19),

        ;

        private final String name;
        public final int VAL;

        Argon2(String name, int val) {
            this.name = name;
            this.VAL = val;
        }

        public String getName() {
            return name;
        }



//        static NVGenericMap hashPassword(byte[] password) {
//
//            byte[] salt = SecUtil.SINGLETON.generateRandomBytes(SALT_LEN.VAL);
//            byte[] hash = argon2idHash(password, HASH_LEN.VAL, salt, MEMORY.VAL, ROUNDS.VAL, PARALLELISM.VAL);
//            return new NVGenericMap()
//                    .build(new NVBlob(HASH, hash))
//                    .build(new NVBlob(SALT, salt))
//                    .build(new NVInt(MEMORY, MEMORY.VAL))
//                    .build(new NVInt(ROUNDS, ROUNDS.VAL))
//                    .build(new NVInt(PARALLELISM, PARALLELISM.VAL));
//        }


         static boolean validate(byte[] password, CIPassword hashInfo) {
            byte[] storedHash = hashInfo.getHash();
            byte[] passwordHash = argon2idHash(password,
                    storedHash.length,
                    hashInfo.getSalt(),
                    hashInfo.getProperties().getValue(MEMORY),//getValue(MEMORY),
                    hashInfo.getRounds(),
                    hashInfo.getProperties().getValue(PARALLELISM));

            return Arrays.equals(passwordHash, storedHash);
        }


//        String argon2idCanID(String password) {
//            return argon2idCanID(SharedStringUtil.getBytes(password));
//        }
//
//        String argon2idCanID(byte[] password) {
//            byte[] salt = SecUtil.SINGLETON.generateRandomBytes(16);
//            byte[] hash = argon2idHash(password, 32, salt, Const.SizeInBytes.K.mult(15), 2, 1);
//            return argonToCanID("argon2id", 19, hash, salt, Const.SizeInBytes.K.mult(15), 2, 1);
//        }


        static CIPassword parseArgon2PHCString(String phcString) {
            // Result map
            CIPassword result = new CIPassword();

            // Regex for PHC string, groups: algorithm, version, params, salt, hash
            Pattern p = Pattern.compile(
                    "^\\$(argon2(?:id|i|d))\\$v=(\\d+)\\$([a-zA-Z0-9=,]+)\\$([A-Za-z0-9+/=]+)\\$([A-Za-z0-9+/=]+)$"
            );
            Matcher m = p.matcher(phcString.trim());

            if (!m.matches()) {
                throw new IllegalArgumentException("Invalid Argon2 PHC string format");
            }

            // Fill map
            result.setAlgorithm(m.group(1));
            int version = Integer.parseInt(m.group(2));
            result.setVersion(""+version);

            // Parse param string (e.g. m=65536,t=3,p=1)
            String[] params = m.group(3).split(",");
            for (String param : params) {
                String[] nv = param.split("=", 2);

                if (nv.length == 2) {
                    if("t".equalsIgnoreCase(nv[0]))
                        result.setRounds(Integer.parseInt(nv[1]));
                    else
                        result.getProperties().build(new NVInt(nv[0], Integer.parseInt(nv[1])));
                }
            }

            result.setSalt(SharedBase64.decode(SharedBase64.Base64Type.DEFAULT_NP, m.group(4)));
            result.setHash(SharedBase64.decode(SharedBase64.Base64Type.DEFAULT_NP, m.group(5)));
            result.setCanonicalID(phcString);
            return result;
        }


        static String argonToCanID(String alg, int version, byte[] hash, byte[] salt, int memory, int rounds, int parallelism) {
            String base64Salt = SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT_NP, salt);
            String base64Hash = SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT_NP, hash);
            return String.format("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
                    alg, version, memory, rounds, parallelism, base64Salt, base64Hash);
        }


        static byte[] argon2idHash(String password, int hashLength, int saltLength, int memory, int rounds, int parallelism) {
            return argon2idHash(SharedStringUtil.getBytes(password), hashLength, saltLength, memory, rounds, parallelism);
        }

        static byte[] argon2idHash(byte[] password, int hashLength, int saltLength, int memory, int rounds, int parallelism) {
            return argon2idHash(password, hashLength, SecUtil.generateRandomBytes(saltLength), memory, rounds, parallelism);
        }

        static byte[] argon2idHash(String password, int hashLength, byte[] salt, int memory, int rounds, int parallelism) {
            return argon2idHash(SharedStringUtil.getBytes(password), hashLength, salt, memory, rounds, parallelism);
        }

        static byte[] argon2idHash(byte[] password, int hashLength, byte[] salt, int memory, int rounds, int parallelism) {


            Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withSalt(salt)
                    .withIterations(rounds)
                    .withMemoryAsKB(memory)
                    .withParallelism(parallelism);

            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(builder.build());

            byte[] hash = new byte[hashLength];
            generator.generateBytes(password, hash);
            return hash;
        }


    }


    private final int memory;
    private final int parallelism;
    private final int saltLength;
    private final int hashLength;

    public ArgonPasswordHasher()
    {
        this(Argon2.MEMORY.VAL, Argon2.ROUNDS.VAL, Argon2.PARALLELISM.VAL, Argon2.SALT_LEN.VAL, Argon2.HASH_LEN.VAL);
    }


    public ArgonPasswordHasher(int memory, int rounds, int parallelism, int saltLen, int hashLen) {
        super(CryptoConst.HashType.ARGON2.getName(), CryptoConst.HashType.ARGON2, CryptoConst.HashType.ARGON2.VARIANCES, rounds);
        this.memory = memory;
        this.parallelism = parallelism;
        this.saltLength = saltLen;
        this.hashLength = hashLen;
    }


    @Override
    public CIPassword hash(String password) {
        return hash(SharedStringUtil.getBytes(password));
    }

    @Override
    public CIPassword hash(byte[] password) {

        CIPassword result = new CIPassword();
        byte[] salt = SecUtil.generateRandomBytes(saltLength);
        byte[] hash = Argon2.argon2idHash(password, hashLength, salt, memory, getRounds(), parallelism);
        result.setAlgorithm("argon2id");
        result.setVersion("" + Argon2.VERSION.VAL);
        result.setSalt(salt);
        result.setHash(hash);
        result.setRounds(getRounds());

        result.getProperties()
                .build(new NVInt(Argon2.MEMORY, memory))
                .build(new NVInt(Argon2.PARALLELISM, parallelism));

        result.setCanonicalID(Argon2.argonToCanID(result.getAlgorithm(),
                Integer.parseInt(result.getVersion()),
                result.getHash(),
                result.getSalt(),
                result.getProperties().getValue(Argon2.MEMORY),
                result.getRounds(),
                result.getProperties().getValue(Argon2.PARALLELISM)));
        return result;
    }

    @Override
    public CIPassword hash(char[] password) {
        return hash(ByteBufferUtil.toBytes(password));
    }

    @Override
    public CIPassword fromCanonicalID(String passwordCanID) {
        return Argon2.parseArgon2PHCString(passwordCanID);
    }

    @Override
    public boolean validate(CIPassword ci, String password) {
        return Argon2.validate(SharedStringUtil.getBytes(password), ci);
    }

    @Override
    public boolean validate(CIPassword ci, byte[] password) {
        return Argon2.validate(password, ci);
    }

    @Override
    public boolean validate(CIPassword ci, char[] password) {
        return Argon2.validate(ByteBufferUtil.toBytes(password), ci);
    }
}
