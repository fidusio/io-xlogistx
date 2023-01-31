package io.xlogistx.common.crypto;

import org.zoxweb.shared.util.GetName;
import org.zoxweb.shared.util.SharedStringUtil;
import org.zoxweb.shared.util.SharedUtil;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class DigestAppender
    implements GetName {

    private final MessageDigest md;
    private final Lock lock = new ReentrantLock();
    private final String name;

    /**
     * Create DigestAppender based on the algorithm name
     * @param algorithmName message digest instance name
     * @throws NoSuchAlgorithmException if the algorithm name do not exist
     */
    public DigestAppender(String algorithmName) throws NoSuchAlgorithmException {
        this(MessageDigest.getInstance(algorithmName), algorithmName);
    }

    /**
     * Create DigestAppend based on the algorithm name and custom appender name
     * @param algorithmName algorithm name
     * @param appenderName custom name
     * @throws NoSuchAlgorithmException if the algorithm name do not exist
     */
    public DigestAppender(String algorithmName, String appenderName) throws NoSuchAlgorithmException {
        this(MessageDigest.getInstance(algorithmName), appenderName);
    }

    /**
     * Create DigestAppend based on the algorithm name and custom appender name
     * @param md message digest
     * @param appenderName custom name
     */
    public DigestAppender(MessageDigest md, String appenderName){
        SharedUtil.checkIfNulls("Message digest null.", md);
        this.md = md;
        this.name = appenderName;
    }

    /**
     * Get the appender customer name
     * @return the custom name
     */
    public String getName(){
        return name;
    }

    /**
     * Append messages to the digest
     * @param messages to be appended
     * @return latest digest
     */
    public byte[] append(byte[] ...messages) {
        try {
            lock.lock();
            justAppend(messages);
            return getMessageDigest().digest();
        }
        finally {
            lock.unlock();
        }

    }

    /**
     * Just append messages
     * @param messages to appended
     */
    public void justAppend(byte[]... messages) {
        try {
            lock.lock();
            for (byte[] message : messages) {
               if (message != null) {
                  md.update(message);
               }
          }
        } finally {
          lock.unlock();
        }
    }

    /**
     * Digest the appender
     * @return the digest hash
     */
    public byte[] digest()
    {
        try{
            lock.lock();
            return md.digest();
        }
        finally{
            lock.unlock();
        }
    }

    /**
     * Append messages and return a hex string hash
     * @param messages to append
     * @return hash string
     */
    public String appendToString(byte[] ...messages) {
        return SharedStringUtil.bytesToHex(append(messages));
    }

    /**
     * Get a clone of the message digest
     * @return clone of the digest
     */
    public MessageDigest getMessageDigest() {
        try {
            lock.lock();

            try {
                return (MessageDigest) md.clone();
            } catch (CloneNotSupportedException e) {
                e.printStackTrace();
                return null;
            }
        }
        finally{
            lock.unlock();
        }

    }

}
