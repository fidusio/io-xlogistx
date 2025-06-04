package io.xlogistx.http.services;

import io.xlogistx.common.data.Challenge;
import io.xlogistx.common.data.ChallengeManager;
import io.xlogistx.common.image.ImageInfo;
import io.xlogistx.common.image.TextToImage;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.SUS;

import java.awt.*;
import java.io.IOException;
import java.util.UUID;

public class CaptchaService {

    public static final LogWrapper log = new LogWrapper(CaptchaService.class).setEnabled(false);

    @EndPointProp(methods = {HTTPMethod.GET}, name = "captcha-create", uris = "/app-captcha")
    public HTTPMessageConfigInterface create() throws IOException {
        if (log.isEnabled()) log.getLogger().info("start ");

        HTTPMessageConfigInterface ret = new HTTPMessageConfig();
        Challenge.Type ct = Challenge.Type.values()[Math.abs(Challenge.SR.nextInt() % Challenge.Type.values().length)];
        int power = 0;
        switch (ct) {
            case ADDITION:
            case SUBTRACTION:
                power = 2;
                break;
            case CAPTCHA:
                power = 5;
                break;
        }


        Challenge challenge = Challenge.generate(ct, power, UUID.randomUUID().toString());
        ImageInfo imageInfo = TextToImage.textToImage(challenge.format() + " ", "gif", new Font("Arial", Font.ITALIC, 18), Color.BLUE, challenge.getId());
        ret.setContentType("image/" + imageInfo.format);
        ret.getHeaders().build("Captcha-Id", imageInfo.id);
        ret.getHeaders().build("Access-Control-Allow-Origin", "*");
        ret.getHeaders().build("Cache-Control", "no-cache, no-store, must-revalidate");
        ret.getHeaders().build("Access-Control-Expose-Headers", "Captcha-Id");

        ChallengeManager.SINGLETON.addChallenge(challenge, Const.TimeInMillis.MINUTE.MILLIS * 30);
        UByteArrayOutputStream imageContent = new UByteArrayOutputStream();

        IOUtil.relayStreams(imageInfo.data, imageContent, true);
        ret.setContent(imageContent.toByteArray());
        ret.setHTTPStatusCode(HTTPStatusCode.OK);
        if (log.isEnabled()) log.getLogger().info("challenge: " + challenge);
        return ret;

    }


    public void validate(String captchaID, String captcha)
            throws HTTPCallException {
        HTTPMessageConfigInterface ret = new HTTPMessageConfig();

        // get the captcha-id and captcha

        if (SUS.isEmpty(captchaID) || SUS.isEmpty(captcha)) {
            // if the captcha data is missing return
            throw new HTTPCallException("Missing CAPTCHA", HTTPStatusCode.BAD_REQUEST);
//            HTTPServletUtil.sendJSON(req, resp, HTTPStatusCode.BAD_REQUEST, new APIError("Missing CAPTCHA"));
//            log.getLogger().info("Captcha parameters are missing.");
//            return Challenge.Status.ERROR;
        }

        // match the captcha-id with the challenge
        Challenge challenge = ChallengeManager.SINGLETON.lookupChallenge(captchaID);
        if (challenge == null) {
            // no challenge found
            throw new HTTPCallException("Missing CAPTCHA", HTTPStatusCode.BAD_REQUEST);
        }
        // parse the captcha value
        long captchaValue = Long.parseLong(captcha);
        if (!ChallengeManager.SINGLETON.validate(challenge, captchaValue)) {

            log.getLogger().info("Captcha challenge mismatch expected: " + challenge.getResult() + " user sent: " + captchaValue);
            throw new HTTPCallException("Captcha Miss match", HTTPStatusCode.UNAUTHORIZED);
        }
    }
}
