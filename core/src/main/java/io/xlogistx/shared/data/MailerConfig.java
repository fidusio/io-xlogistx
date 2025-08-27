package io.xlogistx.shared.data;

import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.filters.FilterType;
import org.zoxweb.shared.util.*;

public class MailerConfig
        extends SetNameDescriptionDAO {

    public enum Param
            implements GetNVConfig {

        SMTP_CONFIG(NVConfigManager
                .createNVConfigEntity("smtp_config", "User", "User", true, true, SMTPConfig.class, NVConfigEntity.ArrayType.NOT_ARRAY)),
        DOCUMENT_TEMPLATE(NVConfigManager
                .createNVConfigEntity("template", "Template", "Template", true, true, DocumentTemplate.class, NVConfigEntity.ArrayType.NOT_ARRAY)),
        FROM(NVConfigManager
                .createNVConfig("from", "Sender email", "From", true, true, false, String.class, FilterType.EMAIL)),
        RECIPIENTS(NVConfigManager
                .createNVConfig("recipients", "Recipient emails", "Recipients", true, true, String.class)),
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

    public static final NVConfigEntity NVC_MAILER_CONFIG = new NVConfigEntityPortable(
            "mailer_config",
            null,
            MailerConfig.class.getSimpleName(),
            true,
            false,
            false,
            false,
            MailerConfig.class,
            SharedUtil.extractNVConfigs(Param.values()),
            null,
            false,
            SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO
    );


    public MailerConfig() {
        super(NVC_MAILER_CONFIG);
    }


    public void setSMTPConfig(SMTPConfig smtpConfig) {
        setValue(Param.SMTP_CONFIG, smtpConfig);
    }

    public SMTPConfig getSMTPConfig() {
        return lookupValue(Param.SMTP_CONFIG);
    }

    public void setDocumentTemplate(DocumentTemplate docTemplate) {
        setValue(Param.DOCUMENT_TEMPLATE, docTemplate);
    }

    public DocumentTemplate getDocumentTemplate() {
        return lookupValue(Param.DOCUMENT_TEMPLATE);
    }

    public String getFrom() {
        return lookupValue(Param.FROM);
    }

    public void setFrom(String email) {
        setValue(Param.FROM, email);
    }

    public String getRecipients() {
        return lookupValue(Param.RECIPIENTS);
    }

    /**
     * Format : "to:email@email.com, bcc:hidden@email.com"
     * @param emails
     */
    public void setRecipients(String emails) {
        setValue(Param.RECIPIENTS, emails);
    }

}
