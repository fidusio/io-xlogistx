package io.xlogistx.shared.data;

import org.junit.jupiter.api.Test;
import org.zoxweb.server.util.GSONUtil;

import java.io.IOException;

public class MailerConfigTest {

    @Test
    public void mailerConfig() throws IOException {
        MailerConfig mc = new MailerConfig();
        SMTPConfig smtpConfig = new SMTPConfig("xlogistx.io", 465, "notify", "Z0b9m8b76");
        DocumentTemplate dt = new DocumentTemplate();
        dt.setContent("Contact message\nName: $$contact-name$$\nCompany: $$company-name$$\nEmail: $$email$$\n\n$$message$$\n\n Send via FormMailer by http://xlogistx.io .");

        dt.setBodyTags("contact-name", "company-name", "email", "message");
        dt.setPreTag("$$");
        dt.setPostTag("$$");
        mc.setSMTPConfig(smtpConfig);
        mc.setDocumentTemplate(dt);
        String json = GSONUtil.toJSON(mc, true, false,true);
        System.out.println(json);
        mc = GSONUtil.fromJSON(json);
        System.out.println(mc.getDocumentTemplate().getContent());
    }
}
