package io.xlogistx.opsec.services;

import io.xlogistx.common.data.PropertyContainer;
import io.xlogistx.common.smtp.EmailRecipient;
import io.xlogistx.common.smtp.SMTPMessage;
import io.xlogistx.common.smtp.SMTPSender;
import io.xlogistx.shared.data.DocumentTemplate;
import io.xlogistx.shared.data.MailerConfig;
import io.xlogistx.shared.data.SMTPConfig;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.http.HTTPMessageConfig;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.security.AccessSecurityException;
import org.zoxweb.shared.security.DomainSecurityManager;
import org.zoxweb.shared.security.PasswordResetRequest;
import org.zoxweb.shared.security.SecConst;
import org.zoxweb.shared.security.model.SecurityModel;
import org.zoxweb.shared.util.*;

import java.util.Date;

/**
 * Password-reset endpoints over the {@link DomainSecurityManager} registered in
 * {@link ResourceManager} under {@code Resource.DOMAIN_SECURITY_MANAGER} (the shiro-ds manager
 * registers itself there on {@code installAsGlobal()} / {@code attach}).
 * <p>
 * Properties (endpoint config): {@code reset-mailer-config} — a {@code MailerConfig} whose
 * {@code smtp_config} sends the mail and whose {@code template} body may carry the tags
 * {@code principal_id}, {@code token}, {@code reset_url}, {@code expiry}; {@code reset-url} — a URL
 * template with the same tags, e.g. {@code https://host/reset?pid=$$principal_id$$&token=$$token$$}
 * (tags use the template's pre/post markers; {@code $$} when the template has none).
 * <p>
 * {@code reset-request} never reveals whether a principal exists: it answers 202 in every case and
 * sends the mail asynchronously. Rate limiting per principal and per source is a deployment concern
 * in front of these endpoints.
 */
public class PasswordReset
        extends PropertyContainer<NVGenericMap> {

    public static final LogWrapper log = new LogWrapper(PasswordReset.class).setEnabled(false);
    public static final String PROP_MAILER_CONFIG = "reset-mailer-config";
    public static final String PROP_RESET_URL = "reset-url";
    public static final String TAG_PRINCIPAL_ID = "principal_id";
    public static final String TAG_TOKEN = "token";
    public static final String TAG_RESET_URL = "reset_url";
    public static final String TAG_EXPIRY = "expiry";
    private static final String DEFAULT_TAG_MARK = "$$";

    private volatile MailerConfig mailerConfig;
    private volatile String resetURLTemplate;

    @EndPointProp(methods = {HTTPMethod.POST}, name = "password-reset-request", uris = "/opsec/password/reset-request")
    @SecurityProp(authentications = {SecConst.AuthenticationType.NONE})
    public HTTPMessageConfigInterface resetRequest(@ParamProp(name = "", source = Const.ParamSource.PAYLOAD) NVGenericMap payload) {
        String principalID = payload != null ? payload.getValue(TAG_PRINCIPAL_ID) : null;
        try {
            if (!SUS.isEmpty(principalID)) {
                PasswordResetRequest req = dsm().requestPasswordReset(principalID);
                TaskUtil.defaultTaskScheduler().queue(0, () -> deliver(req));
            }
        } catch (Exception e) {
            // unknown principal, no email principal, inactive subject, ...: same answer, reason logged only
            if (log.isEnabled()) log.getLogger().info("reset-request for " + principalID + " not issued: " + e);
        }
        return status(HTTPStatusCode.ACCEPTED, null);
    }

    @EndPointProp(methods = {HTTPMethod.POST}, name = "password-reset-confirm", uris = "/opsec/password/reset-confirm")
    @SecurityProp(authentications = {SecConst.AuthenticationType.NONE})
    public HTTPMessageConfigInterface resetConfirm(@ParamProp(name = "", source = Const.ParamSource.PAYLOAD) NVGenericMap payload) {
        String principalID = payload != null ? payload.getValue(TAG_PRINCIPAL_ID) : null;
        String token = payload != null ? payload.getValue(TAG_TOKEN) : null;
        String newPassword = payload != null ? payload.getValue("new_password") : null;
        try {
            dsm().completePasswordReset(principalID, token, newPassword);
            return status(HTTPStatusCode.NO_CONTENT, null);
        } catch (IllegalArgumentException | NullPointerException e) {
            return status(HTTPStatusCode.BAD_REQUEST, "new password rejected: " + e.getMessage());
        } catch (AccessSecurityException e) {
            return status(HTTPStatusCode.BAD_REQUEST, "Invalid or expired reset token");
        }
    }

    @EndPointProp(methods = {HTTPMethod.POST}, name = "password-admin-reset", uris = "/opsec/password/admin-reset")
    @SecurityProp(authentications = {SecConst.AuthenticationType.ALL}, permissions = SecurityModel.PERM_UPDATE_SUBJECT)
    public NVGenericMap adminReset(@ParamProp(name = "", source = Const.ParamSource.PAYLOAD) NVGenericMap payload) {
        String principalID = payload != null ? payload.getValue(TAG_PRINCIPAL_ID) : null;
        PasswordResetRequest req = dsm().adminResetPassword(principalID);
        NVGenericMap ret = new NVGenericMap();
        ret.build(TAG_PRINCIPAL_ID, req.getPrincipalID());
        ret.build(TAG_TOKEN, req.getToken());
        ret.add(new NVLong("expiry_ts", req.getExpiryTS()));
        ret.build("channel", req.getChannel().name());
        ret.build("delivery_principals", String.join(",", req.getDeliveryPrincipalIDs()));
        return ret;
    }

    private DomainSecurityManager dsm() {
        DomainSecurityManager ret = ResourceManager.lookupResource(ResourceManager.Resource.DOMAIN_SECURITY_MANAGER);
        if (ret == null) {
            throw new IllegalStateException("No DomainSecurityManager registered under "
                    + ResourceManager.Resource.DOMAIN_SECURITY_MANAGER.getName());
        }
        return ret;
    }

    private static HTTPMessageConfigInterface status(HTTPStatusCode code, String text) {
        HTTPMessageConfigInterface ret = new HTTPMessageConfig();
        ret.setHTTPStatusCode(code);
        ret.setContentType("text/plain");
        ret.setContent(text != null ? text : "");
        ret.getHeaders().build("Cache-Control", "no-cache, no-store, must-revalidate");
        return ret;
    }

    /** Mails the token to every email principal; failures are logged, never surfaced. */
    private void deliver(PasswordResetRequest req) {
        MailerConfig cfg = mailerConfig;
        if (cfg == null || cfg.getSMTPConfig() == null) {
            log.getLogger().warning("reset-request issued for " + req.getPrincipalID() + " but no " + PROP_MAILER_CONFIG + " is configured");
            return;
        }
        try {
            SMTPConfig sc = cfg.getSMTPConfig();
            DocumentTemplate template = cfg.getDocumentTemplate();
            String pre = template != null && template.getPreTag() != null ? template.getPreTag() : DEFAULT_TAG_MARK;
            String post = template != null && template.getPostTag() != null ? template.getPostTag() : DEFAULT_TAG_MARK;
            String url = resetURLTemplate != null ? fill(resetURLTemplate, pre, post, req, null) : null;
            String title = template != null && template.getTitle() != null ? template.getTitle() : "Password reset";
            String body = template != null && template.getContent() != null ? template.getContent()
                    : "A password reset was requested for " + pre + TAG_PRINCIPAL_ID + post + ".\n"
                    + (url != null ? "Open " + pre + TAG_RESET_URL + post + "\n" : "Token: " + pre + TAG_TOKEN + post + "\n")
                    + "The token expires on " + pre + TAG_EXPIRY + post + ".\nIf you did not ask for this, ignore this message.";
            body = fill(body, pre, post, req, url);

            SMTPMessage message = new SMTPMessage(title, body);
            message.setFrom(!SUS.isEmpty(cfg.getFrom()) ? cfg.getFrom() : sc.getUser());
            for (String email : req.getDeliveryPrincipalIDs()) {
                message.addRecipient(EmailRecipient.Type.TO, email);
            }
            SMTPSender.sendEmail(sc, message);
        } catch (Exception e) {
            log.getLogger().warning("reset mail for " + req.getPrincipalID() + " failed: " + e);
        }
    }

    private static String fill(String text, String pre, String post, PasswordResetRequest req, String url) {
        text = SharedStringUtil.embedText(text, pre + TAG_PRINCIPAL_ID + post, req.getPrincipalID());
        text = SharedStringUtil.embedText(text, pre + TAG_TOKEN + post, req.getToken());
        text = SharedStringUtil.embedText(text, pre + TAG_EXPIRY + post, new Date(req.getExpiryTS()).toString());
        if (url != null) {
            text = SharedStringUtil.embedText(text, pre + TAG_RESET_URL + post, url);
        }
        return text;
    }

    @Override
    protected void refreshProperties() {
        mailerConfig = getProperties() != null ? getProperties().getValue(PROP_MAILER_CONFIG) : null;
        resetURLTemplate = getProperties() != null ? getProperties().getValue(PROP_RESET_URL) : null;
    }
}
