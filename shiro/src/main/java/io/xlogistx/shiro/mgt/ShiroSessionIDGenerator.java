package io.xlogistx.shiro.mgt;

import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.eis.SessionIdGenerator;
import org.zoxweb.server.security.SecUtil;
import org.zoxweb.shared.util.SUS;

import java.io.Serializable;
import java.security.SecureRandom;

public class ShiroSessionIDGenerator
        implements SessionIdGenerator {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    public static final int NUM_BYTES = 32; // 256 bits

    @Override
    public Serializable generateId(Session session) {
        return SUS.fastBytesToHex(SecUtil.generateRandomBytes(SECURE_RANDOM, NUM_BYTES));
    }

}
