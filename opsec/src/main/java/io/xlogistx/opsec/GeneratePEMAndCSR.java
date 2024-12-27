package io.xlogistx.opsec;


import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.shared.util.ParamUtil;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.security.KeyPair;

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
            String attrs = params.stringValue("attrs");
            KeyPair keyPair = OPSecUtil.generateKeyPair(keyType, "BC");


            String filename = OPSecUtil.extractFilename(attrs);



            UByteArrayOutputStream keyBAOS = new UByteArrayOutputStream();
            // Save Private Key to PEM file
            try (Writer writer = new OutputStreamWriter(keyBAOS))
            {
                JcaPEMWriter pemWriter = new JcaPEMWriter(writer);


//                String[] parsed = keyType.split("[ ,:]");
//                if (parsed.length != 2)
//                {
//                    throw new IllegalArgumentException("invalid key " + keyType + " ie:  rsa 2048 or ec:secp256r1 or use , as separator");
//                }
//                String parsedType = parsed[0].toUpperCase();
//                String parsedSpec = parsed[1];
//                if ("EC".equals(parsedType))
//                {
//                    // this a hack really should not be done like this
//                    // just to fix a bug
//                    switch(parsedSpec.toLowerCase())
//                    {
//                        case "secp256r1":
//                            keyBAOS.write(OPSecUtil.BEGIN_EC_PARAM +"\n");
//                            keyBAOS.write(OPSecUtil.SECP_256_R1_EC_VAL +"\n");
//                            keyBAOS.write(OPSecUtil.END_EC_PARAM+"\n");
//                            break;
//                        case "secp384r1":
//                            keyBAOS.write(OPSecUtil.BEGIN_EC_PARAM +"\n");
//                            keyBAOS.write(OPSecUtil.SECP_384_R1_EC_VAL +"\n");
//                            keyBAOS.write(OPSecUtil.END_EC_PARAM+"\n");
//                            break;
//                        default:
//                            throw new IllegalArgumentException("Unsupported " + keyType);
//
//                    }
//                }


                pemWriter.writeObject(keyPair.getPrivate());
                pemWriter.close();
                os = new FileOutputStream(OPSecUtil.outputFilename(outDir, filename + ".key"));
                keyBAOS.writeTo(os);
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


            System.out.println(keyBAOS.toString());

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
