package io.xlogistx.opsec;


import org.zoxweb.shared.util.SharedStringUtil;

import java.io.FileInputStream;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.concurrent.atomic.AtomicLong;

public class CRLReader {
    public static void main(String[] args) throws Exception {


        try (FileInputStream fis = new FileInputStream(args[0])) {
            String match = args.length >= 2 ? args[1] : null;
            if (match != null)
                match = match.replace(":", "");
            X509CRL crl = OPSecUtil.SINGLETON.readCRL(fis);

            System.out.println("Issuer: " + crl.getIssuerX500Principal());
            System.out.println("This Update: " + crl.getThisUpdate());
            System.out.println("Next Update: " + crl.getNextUpdate());
            System.out.println("Revoked Certificates:");
            AtomicLong counter = new AtomicLong();
            String copy = match;
            for (X509CRLEntry rev : OPSecUtil.SINGLETON.getRevokedCerts(crl)) {

                String serial = SharedStringUtil.bytesToHex(rev.getSerialNumber().toByteArray());
                System.out.println("  Serial: " + serial + " Revoked: " + rev.getRevocationDate());
                if (serial.equals(copy)) {
                    System.out.println("match is revoked");
                    System.exit(-1);
                }
                counter.incrementAndGet();
            }
            ;

            System.out.println("Total: " + counter.get() + " match not found: " + copy);
        }
    }
}