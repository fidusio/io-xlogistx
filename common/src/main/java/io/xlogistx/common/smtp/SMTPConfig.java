package io.xlogistx.common.smtp;

public class SMTPConfig
{
    public final String user;
    protected final String password;
    public final String host;
    public final int port;

    public SMTPConfig(String host, int port, String user, String password)
    {
        this.host = host;
        this.port = port;
        this.user = user;
        this.password = password;
    }
}