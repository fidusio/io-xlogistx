package io.xlogistx.shared.data;


import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.filters.FilterType;
//import org.zoxweb.shared.filters.ValueFilter;
import org.zoxweb.shared.util.*;

public class SMTPConfig
        extends SetNameDescriptionDAO {

    public enum Param
            implements GetNVConfig {

        TOKEN(NVConfigManager
                .createNVConfig("token", "Email token", "Token", false, true, String.class)),
        USER(NVConfigManager
                .createNVConfig("user", "User", "User", true, true, String.class)),
        PASSWORD(NVConfigManager
                .createNVConfig("password", "Password", "Password", true, true, false, String.class, FilterType.ENCRYPT)),
        HOST(NVConfigManager
                .createNVConfig("host", "Hostname", "Hostname", true, true, String.class)),
        PORT(NVConfigManager
                .createNVConfig("port", "Port", "Port", true, true, int.class)),
        TRUST(NVConfigManager
                .createNVConfig("trust", "Trust this host", "Trust", false, true, boolean.class)),

        ;

        private final NVConfig nvc;

        Param(NVConfig nvc) {
            this.nvc = nvc;
        }

        @Override
        public NVConfig getNVConfig() {
            return nvc;
        }
    }

    public static final NVConfigEntity NVC_SMTP_CONFIG = new NVConfigEntityPortable(
            "smtp_config",
            null,
            SMTPConfig.class.getSimpleName(),
            true,
            false,
            false,
            false,
            SMTPConfig.class,
            SharedUtil.extractNVConfigs(Param.values()),
            null,
            false,
            SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO
    );

    public SMTPConfig() {
        super(NVC_SMTP_CONFIG);
    }

    public SMTPConfig(String host, int port, String user, String password) {
        this();
        setHost(host);
        setPort(port);
        setUser(user);
        setPassword(password);

    }

    public void setHost(String host) {
        setValue(Param.HOST, host);
    }

    public String getHost() {
        return lookupValue(Param.HOST);
    }

    public void setPort(int port) {
        setValue(Param.PORT, port);
    }

    public int getPort() {
        return lookupValue(Param.PORT);
    }


    public void setUser(String user) {
        setValue(Param.USER, user);
    }

    public String getUser() {
        return lookupValue(Param.USER);
    }

    public void setPassword(String password) {
        setValue(Param.PASSWORD, password);
    }

    public String getPassword() {
        return lookupValue(Param.PASSWORD);
    }

    public boolean isTrusted() {
        return lookupValue(Param.TRUST);
    }

    public void setTrusted(boolean trust) {
        setValue(Param.TRUST, trust);
    }

    public String getToken() {
        return lookupValue(Param.TOKEN);
    }

    public void setToken(String token) {
        setValue(Param.TOKEN, token);
    }


}