package io.xlogistx.common.ssh;


import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import org.zoxweb.shared.util.SharedStringUtil;
import org.zoxweb.shared.util.SharedUtil;

import java.util.Properties;

public class SSHClient {
    public static Session connect(String username, String password, String host)
            throws JSchException
    {

        JSch jsch = new JSch();
        Session session = jsch.getSession(username, host, 22);
        session.setPassword(password);

        // Avoid asking for key confirmation
        Properties prop = new Properties();
        prop.put("StrictHostKeyChecking", "no");
        session.setConfig(prop);

        session.connect();
        return session;
    }


    public static void main(String ...args)
    {
        try
        {
            int index = 0;
            String[] userHost = SharedStringUtil.parseString(args[index++], "@",true);
            String user = userHost[0];
            String host = userHost[1];
            System.out.println(user + " " + host);
            String password = args[index++];
            Session session = connect(user, password, host);
            session.sendKeepAliveMsg();
            System.out.println(SharedUtil.toCanonicalID(',', session.getClientVersion(), session.getServerVersion(),
                    session.getUserName()));

            session.disconnect();
        }
        catch(Exception e)
        {
            e.printStackTrace();
            System.err.println("usage: user@host password");
        }
    }
}
