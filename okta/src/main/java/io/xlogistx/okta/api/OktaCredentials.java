package io.xlogistx.okta.api;

import com.google.gson.annotations.SerializedName;
import org.zoxweb.shared.crypto.BCryptHash;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NVInt;

public class OktaCredentials
{

    private NVGenericMap password = null;
    @SerializedName("recovery_question")
    private NVGenericMap recoveryQuestion = null;


    public synchronized NVGenericMap getPassword(){
        if(password == null)
            password = new NVGenericMap();
        return  password;
    }

    public String getPlainPassword()
    {
        return getPassword().getValue("value");
    }

    public OktaCredentials setPlainPassword(String passwd)
    {
        getPassword().add("value", passwd);
        return this;
    }

    public synchronized NVGenericMap getRecoveryQuestion()
    {
        if(recoveryQuestion == null)
            recoveryQuestion = new NVGenericMap();
        return recoveryQuestion;
    }

    public synchronized OktaCredentials setBCrypt(String fullBCryptHash)
    {
        BCryptHash bh = new BCryptHash(fullBCryptHash);
        NVGenericMap hash = getHash();
        hash.add("algorithm", CryptoConst.HASHType.BCRYPT.name());
        hash.add(new NVInt("workFactor", bh.logRound));
        hash.add("salt", bh.salt);
        hash.add("value", bh.hash);

        return this;
    }

    public synchronized NVGenericMap getHash()
    {
        if(getPassword().get("hash") == null)
            getPassword().add(new NVGenericMap("hash"));
        return (NVGenericMap) getPassword().get("hash");
    }

}
