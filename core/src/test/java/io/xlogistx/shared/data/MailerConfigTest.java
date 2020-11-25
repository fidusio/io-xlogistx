package io.xlogistx.shared.data;

import org.junit.jupiter.api.Test;
import org.zoxweb.server.util.GSONUtil;

import java.io.IOException;

public class MailerConfigTest {

    @Test
    public void mailerConfig() throws IOException {
        MailerConfig mc = new MailerConfig();
        SMTPConfig smtpConfig = new SMTPConfig("xlogistx.io", 465, "batata", "batataPwd");
        DocumentTemplate dt = new DocumentTemplate();
        dt.setContent("Hello Mr. $$name$$");
        dt.setBodyTags("name");
        dt.setPreTag("$$");
        dt.setPostTag("$$");
        mc.setSMTPConfig(smtpConfig);
        mc.setDocumentTemplate(dt);

        System.out.println(GSONUtil.toJSON(mc, true, false,false));
    }
}
