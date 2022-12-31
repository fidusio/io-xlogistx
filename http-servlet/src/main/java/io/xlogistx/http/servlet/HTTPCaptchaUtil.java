package io.xlogistx.http.servlet;

import io.xlogistx.common.data.Challenge;

import io.xlogistx.common.data.ChallengeManager;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.api.APIError;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.util.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;



public final class HTTPCaptchaUtil {

    public final static LogWrapper log = new LogWrapper(HTTPCaptchaUtil.class);
    private HTTPCaptchaUtil(){}

    public static Challenge.Status validateCaptcha(ArrayValues<GetNameValue<String>> formData,
                                                   HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Challenge challenge = null;


        // get the captcha-id and captcha
        GetNameValue<String> captchaIDParam = formData.get("captcha-id");
        GetNameValue<String> captchaParam = formData.get("captcha");
        if(captchaIDParam == null || SharedStringUtil.isEmpty(captchaIDParam.getValue()) ||
                captchaParam == null || SharedStringUtil.isEmpty(captchaParam.getValue()))
        {
            // if the captcha data is missing return
            HTTPServletUtil.sendJSON(req, resp, HTTPStatusCode.BAD_REQUEST, new APIError("Missing CAPTCHA"));
            log.getLogger().info("Captcha parameters are missing.");
            return Challenge.Status.ERROR;
        }

        // match the captcha-id with the challenge
        challenge = ChallengeManager.SINGLETON.lookupChallenge(captchaIDParam.getValue());
        if(challenge == null)
        {
            // no challenge found
            HTTPServletUtil.sendJSON(req, resp, HTTPStatusCode.BAD_REQUEST, new APIError("Missing CAPTCHA"));
            log.getLogger().info("Captcha challenge not found for " + captchaIDParam.getValue());
            return Challenge.Status.MISSING_CORRELATION;
        }
        // parse the captcha value
        long captchaValue = Long.parseLong(captchaParam.getValue());
        if(!ChallengeManager.SINGLETON.validate(challenge, captchaValue))
        {
            // challenge failed
            HTTPServletUtil.sendJSON(req, resp, HTTPStatusCode.BAD_REQUEST, new APIError("Invalid CAPTCHA"));
            log.getLogger().info("Captcha challenge mismatch expected: " + challenge.getResult() + " user sent: " + captchaValue);
            return Challenge.Status.INVALID;
        }




        return Challenge.Status.VALID;
    }
}
