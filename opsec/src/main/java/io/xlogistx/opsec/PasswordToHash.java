package io.xlogistx.opsec;

import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.security.SecUtil;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.crypto.CredentialHasher;
import org.zoxweb.shared.util.SharedStringUtil;

import java.io.Console;
import java.util.Arrays;
import java.util.Scanner;

public class PasswordToHash {

    private static void error(String msg, int errorCode) {
        System.err.println("**Error**: " + msg);
        System.err.println("usage: [aglo] [password]");
        System.exit(errorCode);
    }

    public static void main(String[] args) {
        OPSecUtil.SINGLETON.loadProviders();
        try {
            int index = 0;
            String algo = args[index++];
            String rawPassword = index < args.length ? args[index] : null;

            CredentialHasher<CIPassword> credentialHasher = SecUtil.lookupCredentialHasher(algo);
            if(credentialHasher == null)
                throw new IllegalArgumentException("invalid aglo: " +algo);

            System.out.println("PasswordHasher type: " + algo);
            if (rawPassword == null) {
                Console console = System.console();
                if (console != null) {
                    char[] passwd1 = console.readPassword("Enter your password: ");
                    char[] passwd2 = console.readPassword("Re enter your password: ");
                    if (!Arrays.equals(passwd1, passwd2))
                        error("Password miss match", -1);

                    rawPassword = SharedStringUtil.toString(passwd1);

                } else {
                    // use the scanner
                    Scanner scanner = new Scanner(System.in);
                    System.out.print("Enter password:");
                    String passwd1 = scanner.nextLine();
                    System.out.print("Re enter password:");
                    String passwd2 = scanner.nextLine();
                    if (!passwd1.equals(passwd2))
                        error("Password miss match", -1);

                    rawPassword = passwd1;
                    IOUtil.close(scanner);
                }

            }

            System.out.println(Arrays.toString(SecUtil.credentialHasherAlgorithms()));

            for(int i = 0; i < 5; i++) {
                CIPassword passwordDAO = credentialHasher.hash(rawPassword);
                System.out.println(passwordDAO.toCanonicalID());
                SecUtil.validatePassword(passwordDAO, rawPassword);
            }
        } catch (Exception e) {
            e.printStackTrace();
            error("error " +  Arrays.toString(SecUtil.credentialHasherAlgorithms()), -1);

        }

    }
}
