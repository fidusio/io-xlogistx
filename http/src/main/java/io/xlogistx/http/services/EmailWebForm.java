package io.xlogistx.http.services;

import io.xlogistx.common.data.ChallengeManager;
import io.xlogistx.common.data.PropertyContainer;
import io.xlogistx.common.smtp.EmailRecipient;
import io.xlogistx.common.smtp.SMTPMessage;
import io.xlogistx.common.smtp.SMTPSender;
import io.xlogistx.shared.data.DocumentTemplate;
import io.xlogistx.shared.data.MailerConfig;
import io.xlogistx.shared.data.SMTPConfig;
import jakarta.mail.MessagingException;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.util.*;

import java.io.IOException;

public class EmailWebForm
        extends PropertyContainer<NVGenericMap> {
    public static final LogWrapper log = new LogWrapper(EmailWebForm.class).setEnabled(true);
    private MailerConfig mailerConfig;


    @EndPointProp(methods = {HTTPMethod.POST}, name = "web-form-to-mail-generic", uris = "/form/generic-mailer/{domain}/{source}")
    public HTTPMessageConfigInterface webMailerGeneric(@ParamProp(name = "domain") String domain,
                                                       @ParamProp(name = "source") String source,
                                                       @ParamProp(name = "nvgm", source = Const.ParamSource.PAYLOAD, optional = true) NVGenericMap payload)
            throws IOException {

        HTTPMessageConfigInterface ret = new HTTPMessageConfig();

        String captchaID = payload.getValue("captcha-id");
        String captchaValue = payload.getValue("captcha");
        String redirectURL = payload.getValue("redirect_url");

        if (log.isEnabled())
            log.getLogger().info("data: " + SUS.toCanonicalID(',', domain, source, captchaID, captchaValue, redirectURL));

        if (!ChallengeManager.SINGLETON.validate(captchaID, captchaValue)) {
//            throw new HTTPCallException("Invalid captcha " + captchaValue);

            ret.setHTTPStatusCode(HTTPStatusCode.UNAUTHORIZED);
            ret.setContentType("text/html");
            ret.setContent("Captcha Validation Failed " + captchaValue);
            ret.getHeaders().build("Access-Control-Allow-Origin", "*");
            ret.getHeaders().build("Cache-Control", "no-cache, no-store, must-revalidate");
            return ret;
        }


        try {
            SMTPConfig sc = mailerConfig.getSMTPConfig();
            DocumentTemplate docTemplate = mailerConfig.getDocumentTemplate();
//            String content = docTemplate.getContent();
            payload.remove("captcha-id");
            payload.remove("captcha");
            payload.remove("redirect_url");
            StringBuilder content = new StringBuilder("Email-Generic form\n");
            for (GetNameValue<?> gnv : payload.values()) {
                content.append(gnv.getName());
                content.append(" : ");
                content.append(gnv.getValue());
                content.append("\n");

            }


//            for (String tagId : docTemplate.getBodyTags()) {
//                String tag = docTemplate.getPreTag() + tagId + docTemplate.getPostTag();
//
//                try {
//                    GetNameValue<String> gnvTag = payload.getNV(tagId);
//                    String value = (gnvTag != null && !SUS.isEmpty(gnvTag.getValue())) ? gnvTag.getValue() : "NP";
//                    content = SharedStringUtil.embedText(content, tag, value);
//                } catch (Exception e) {
//                    e.printStackTrace();
//                }
//            }


            SMTPMessage smtpMessage = new SMTPMessage(docTemplate.getTitle(), content.toString());
            smtpMessage.setFrom(sc.getUser());
            smtpMessage.addRecipients(EmailRecipient.toRecipients(mailerConfig.getRecipients()));


            SMTPSender.sendEmail(sc, smtpMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }

        ret.setHTTPStatusCode(HTTPStatusCode.FOUND);
        ret.setContentType("text/html");
        ret.setContent(Const.EMPTY_BYTE_ARRAY);
        ret.getHeaders().build(HTTPHeader.LOCATION, redirectURL);
//        ret.getHeaders().build(HTTPHeader.ACCESS_CONTROL_ALLOW_ORIGIN, "*");
        ret.getHeaders().build(HTTPHeader.CACHE_CONTROL, "no-cache, no-store, must-revalidate");


        return ret;
    }


    @EndPointProp(methods = {HTTPMethod.POST}, name = "web-form-to-mail", uris = "/form/mailer/{domain}/{source}")
    public HTTPMessageConfigInterface webMailer(@ParamProp(name = "domain") String domain,
                                                @ParamProp(name = "source") String source,
                                                @ParamProp(name = "contact-name", source = Const.ParamSource.QUERY, optional = true) String contactName,
                                                @ParamProp(name = "contact-phone", source = Const.ParamSource.QUERY, optional = true) String contactPhone,
                                                @ParamProp(name = "company-name", source = Const.ParamSource.QUERY, optional = true) String companyName,
                                                @ParamProp(name = "email", source = Const.ParamSource.QUERY) String email,
                                                @ParamProp(name = "message", source = Const.ParamSource.QUERY) String message,
                                                @ParamProp(name = "redirect_url", source = Const.ParamSource.QUERY) String redirectURL,
                                                @ParamProp(name = "captcha-id", source = Const.ParamSource.QUERY) String captchaID,
                                                @ParamProp(name = "captcha", source = Const.ParamSource.QUERY) String captchaValue)
            throws IOException, MessagingException {
        HTTPMessageConfigInterface ret = new HTTPMessageConfig();
        if (log.isEnabled())
            log.getLogger().info("data: " + SUS.toCanonicalID(',', domain, source, contactName, contactPhone, companyName, email, message, redirectURL, captchaID, captchaValue));


        if (!ChallengeManager.SINGLETON.validate(captchaID, captchaValue)) {
//            throw new HTTPCallException("Invalid captcha " + captchaValue);

            ret.setHTTPStatusCode(HTTPStatusCode.UNAUTHORIZED);
            ret.setContentType("text/html");
            ret.setContent("Captcha Validation Failed " + captchaValue);
            ret.getHeaders().build("Access-Control-Allow-Origin", "*");
            ret.getHeaders().build("Cache-Control", "no-cache, no-store, must-revalidate");
            return ret;
        }


        try {
            SMTPConfig sc = mailerConfig.getSMTPConfig();
            DocumentTemplate docTemplate = mailerConfig.getDocumentTemplate();
            String content = docTemplate.getContent();
            NVGenericMap formData = new NVGenericMap()
                    .build("contact-name", contactName)
                    .build("company-name", companyName)
                    .build("contact-phone", contactPhone)
                    .build("email", email)
                    .build("message", message);

            for (String tagId : docTemplate.getBodyTags()) {
                String tag = docTemplate.getPreTag() + tagId + docTemplate.getPostTag();

                try {
                    GetNameValue<String> gnvTag = formData.getNV(tagId);
                    String value = (gnvTag != null && !SUS.isEmpty(gnvTag.getValue())) ? gnvTag.getValue() : "NP";
                    content = SharedStringUtil.embedText(content, tag, value);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }


            SMTPMessage smtpMessage = new SMTPMessage(docTemplate.getTitle(), content);
            smtpMessage.setFrom(sc.getUser());
            smtpMessage.addRecipients(EmailRecipient.toRecipients(mailerConfig.getRecipients()));


            SMTPSender.sendEmail(sc, smtpMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }

        ret.setHTTPStatusCode(HTTPStatusCode.FOUND);
        ret.setContentType("text/html");
        ret.setContent(Const.EMPTY_BYTE_ARRAY);
        ret.getHeaders().build(HTTPHeader.LOCATION, redirectURL);
//        ret.getHeaders().build(HTTPHeader.ACCESS_CONTROL_ALLOW_ORIGIN, "*");
        ret.getHeaders().build(HTTPHeader.CACHE_CONTROL, "no-cache, no-store, must-revalidate");


        return ret;
    }

    @Override
    protected void refreshProperties() {
        mailerConfig = getProperties().getValue("mailer-config");
//        System.out.println(mailerConfig);

    }
}
