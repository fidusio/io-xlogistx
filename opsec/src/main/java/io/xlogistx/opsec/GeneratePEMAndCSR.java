package io.xlogistx.opsec;


import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.shared.util.ParamUtil;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.security.KeyPair;
import java.security.SecureRandom;

public class GeneratePEMAndCSR
{
    public static void main(String[] args)
    {

        try
        {
            OutputStream os = null;

            ParamUtil.ParamMap params = ParamUtil.parse("=", args);
            String keyType = params.stringValue("keytype");

            String altNames = params.stringValue("alt", true);
            String outDir = params.stringValue("out_dir", true);
            String attrs = params.stringValue("attrs", true);
            KeyPair keyPair = CryptoUtil.generateKeyPair(keyType, SecureRandom.getInstanceStrong());


            String filename = OPSecUtil.extractFilename(attrs);

            // Save Private Key to PEM file
            try (Writer writer = new OutputStreamWriter(new FileOutputStream(OPSecUtil.outputFilename(outDir, filename + ".key"))))
            {
                JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
                pemWriter.writeObject(keyPair.getPrivate());
                pemWriter.close();
            }

            // Generate CSR
            PKCS10CertificationRequest csr = OPSecUtil.generateCSR(keyPair, attrs, altNames);

            // Save CSR to PEM file
            UByteArrayOutputStream csrBAOS = new UByteArrayOutputStream();
            try (Writer writer = new OutputStreamWriter(csrBAOS))
            {
                JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
                pemWriter.writeObject(csr);
                pemWriter.close();
                os = new FileOutputStream(OPSecUtil.outputFilename(outDir, filename + ".csr"));
                csrBAOS.writeTo(os);
            }
            finally
            {
                IOUtil.close(os);
            }

            System.out.println("PEM and CSR files have been generated.\n");

            System.out.println(csrBAOS.toString());

        }
        catch(Exception e)
        {
            e.printStackTrace();
            System.err.println("Usage: GeneratePEMAndCSR keytype=RSA:2048 attrs=\"CN=domain.com,L=LALA LAND\" [alt=\"DNS:www.domain.com\"] [out_dir=/temp/domain]");
            System.err.println("keytype=RSA or EC ie  RSA:2048 or ec:secp256r1");
            System.err.println("attrs=Common Name for the CSR and extra attributes");
            System.err.println("alt=Comma-separated list of Subject Alternative Names (e.g., DNS:example.com,IP:192.168.0.1)");
            System.err.println("out_dir=output dir");
        }
    }

}
