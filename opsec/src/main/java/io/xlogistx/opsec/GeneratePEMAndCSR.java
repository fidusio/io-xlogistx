package io.xlogistx.opsec;


import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.shared.util.ParamUtil;

import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;

public class GeneratePEMAndCSR {
    public static void main(String[] args) {

        try {
            OutputStream os;

            ParamUtil.ParamMap params = ParamUtil.parse("=", args);
            String keyType = params.stringValue("keytype");

            String altNames = params.stringValue("alt", true);
            String outDir = params.stringValue("out_dir", true);
            String attrs = params.stringValue("attrs");
            KeyPair keyPair = OPSecUtil.SINGLETON.generateKeyPair(keyType, "BC");


            String filename = OPSecUtil.SINGLETON.extractFilename(attrs);


            UByteArrayOutputStream keyBAOS = new UByteArrayOutputStream();
            // Save Private Key to PEM file
            try (Writer writer = new OutputStreamWriter(keyBAOS)) {
                JcaPEMWriter pemWriter = new JcaPEMWriter(writer);

                pemWriter.writeObject(keyPair.getPrivate());
                pemWriter.close();
                os = Files.newOutputStream(Paths.get(OPSecUtil.SINGLETON.outputFilename(outDir, filename + ".key")));
                //os = new FileOutputStream(OPSecUtil.SINGLETON.outputFilename(outDir, filename + ".key"));
                keyBAOS.writeTo(os);
            }

            PKCS10CertificationRequest csr;
            if ("EC".equalsIgnoreCase(keyPair.getPublic().getAlgorithm())) {
                // Generate CSR
                csr = OPSecUtil.SINGLETON.createCSR(keyPair, attrs, altNames, "DigitalSignature", "KeyAgreement"/*, "DataEncipherment"*/);
                System.out.println(keyPair.getPublic().getAlgorithm());
            } else
                csr = OPSecUtil.SINGLETON.createCSR(keyPair, attrs, altNames, "DigitalSignature", "KeyEncipherment");


            // Save CSR to PEM file
            UByteArrayOutputStream csrBAOS = new UByteArrayOutputStream();
            try (Writer writer = new OutputStreamWriter(csrBAOS)) {
                JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
                pemWriter.writeObject(csr);
                pemWriter.close();
                os = Files.newOutputStream(Paths.get((OPSecUtil.SINGLETON.outputFilename(outDir, filename + ".csr"))));
                csrBAOS.writeTo(os);
            } finally {
                IOUtil.close(os);
            }

            System.out.println("PEM and CSR files have been generated.\n");


            System.out.println(keyBAOS);

            System.out.println(csrBAOS);

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Usage: GeneratePEMAndCSR keytype=RSA:2048 attrs=\"CN=domain.com,L=LALA LAND\" [alt=\"DNS:www.domain.com\"] [out_dir=/temp/domain]");
            System.err.println("keytype=RSA or EC ie  RSA:2048 or ec:secp256r1");
            System.err.println("attrs=Common Name for the CSR and extra attributes");
            System.err.println("alt=Comma-separated list of Subject Alternative Names (e.g., DNS:example.com,IP:192.168.0.1)");
            System.err.println("out_dir=output dir");
        }
    }

}
