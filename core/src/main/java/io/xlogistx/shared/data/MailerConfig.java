package io.xlogistx.shared.data;

import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.util.*;

public class MailerConfig
        extends SetNameDescriptionDAO
{

    public enum Param
            implements GetNVConfig {

        SMTP_CONFIG(NVConfigManager
                .createNVConfigEntity("smtp_config", "User", "User", true, true, SMTPConfig.class, NVConfigEntity.ArrayType.NOT_ARRAY)),
        DOCUMENT_TEMPLATE(NVConfigManager
                .createNVConfigEntity("template", "Password", "Password", true, true, DocumentTemplate.class, NVConfigEntity.ArrayType.NOT_ARRAY)),


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

    public static final NVConfigEntity NVC_MAILER_CONFIG = new NVConfigEntityLocal(
            "MailerConfig",
            null,
            MailerConfig.class.getSimpleName(),
            true,
            false,
            false,
            false,
            SMTPConfig.class,
            SharedUtil.extractNVConfigs(Param.values()),
            null,
            false,
            SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO
    );


    public MailerConfig()
    {
        super(NVC_MAILER_CONFIG);
    }



    public void setSMTPConfig(SMTPConfig smtpConfig)
    {
        setValue(Param.SMTP_CONFIG, smtpConfig);
    }

    public SMTPConfig getSMTPConfig()
    {
        return lookupValue(Param.SMTP_CONFIG);
    }

    public void setDocumentTemplate(DocumentTemplate docTemplate)
    {
        setValue(Param.DOCUMENT_TEMPLATE, docTemplate);
    }

    public DocumentTemplate getDocumentTemplate()
    {
        return lookupValue(Param.DOCUMENT_TEMPLATE);
    }
}
