package io.xlogistx.payment.paypal;

import org.zoxweb.server.http.HTTPCall;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.api.APITokenDAO;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.NVEntity;
import org.zoxweb.shared.util.NVPair;
import org.zoxweb.shared.util.SharedStringUtil;

import io.xlogistx.payment.paypal.daos.PPAmountDAO;
import io.xlogistx.payment.paypal.daos.PPPaymentDAO;
import io.xlogistx.payment.paypal.daos.PPRefundDAO;

import java.io.IOException;

public class PayPalRestAPI {

    private PayPalRestAPI() {

    }

    public static APITokenDAO OAUTH2Token(String url, String clientID, String clientSecret)
            throws IOException, InstantiationException, IllegalAccessException, ClassNotFoundException, NullPointerException, IllegalArgumentException {

        HTTPMessageConfigInterface hcc = HTTPMessageConfig.createAndInit(url, "/v1/oauth2/token", HTTPMethod.POST);
        hcc.getHeaders().add(new NVPair(HTTPHeader.ACCEPT, HTTPMediaType.APPLICATION_JSON));
        hcc.getHeaders().add(new NVPair(HTTPHeader.ACCEPT_LANGUAGE, "en_US"));

        hcc.setBasicAuthorization(clientID, clientSecret);
        hcc.getParameters().add(new NVPair("grant_type", "client_credentials"));
        HTTPCall hc = new HTTPCall(hcc, null);
        HTTPResponseData rd = hc.sendRequest();
        APITokenDAO ret = GSONUtil.fromJSON(SharedStringUtil.toString(rd.getData()), APITokenDAO.class);

        ret.setCreationTime(System.currentTimeMillis());
        ret.setLastTimeUpdated(System.currentTimeMillis());
        ret.setLastTimeRead(System.currentTimeMillis());
        ret.setExpirationTimeUnit(Const.TimeInMillis.SECOND);

        return ret;
    }

    public static PPPaymentDAO payment(APITokenDAO token, String url, PPPaymentDAO payment)
            throws IOException, InstantiationException, IllegalAccessException, ClassNotFoundException, NullPointerException, IllegalArgumentException {
        HTTPMessageConfigInterface hcc = HTTPMessageConfig.createAndInit(url, "/v1/payments/payment", HTTPMethod.POST);
        hcc.setContentType(HTTPMediaType.APPLICATION_JSON);
        hcc.getHeaders().add(new NVPair(HTTPHeader.ACCEPT, HTTPMediaType.APPLICATION_JSON));
        hcc.getHeaders().add(new NVPair(HTTPHeader.ACCEPT_LANGUAGE, "en_US"));
        //hcc.getHeaderParameters().add(HTTPAuthorizationType.BEARER.toHTTPHeader(token.getTokenType(), token.getAccessToken()));
        hcc.setAuthorization(new HTTPAuthorization(HTTPAuthScheme.BEARER, token.getAccessToken()));
        String json = GSONUtil.toJSON(payment, true, false, false);
        hcc.setContent(SharedStringUtil.getBytes(json));

        System.out.println(GSONUtil.toJSON((NVEntity) hcc, true, false, false));
        HTTPCall hc = new HTTPCall(hcc, null);
        HTTPResponseData rd = hc.sendRequest();

        PPPaymentDAO response = GSONUtil.fromJSON(SharedStringUtil.toString(rd.getData()), PPPaymentDAO.class);
        return response;
    }

    public static PPRefundDAO refund(APITokenDAO token, String url, String refundID, String total, String currency)
            throws IOException, InstantiationException, IllegalAccessException, ClassNotFoundException, NullPointerException, IllegalArgumentException {
        HTTPMessageConfigInterface hcc = HTTPMessageConfig.createAndInit(url, "/v1/payments/sale/" + refundID + "/refund", HTTPMethod.POST);
        hcc.setContentType(HTTPMediaType.APPLICATION_JSON);
        hcc.getHeaders().add(new NVPair(HTTPHeader.ACCEPT, HTTPMediaType.APPLICATION_JSON));
        hcc.getHeaders().add(new NVPair(HTTPHeader.ACCEPT_LANGUAGE, "en_US"));
        //hcc.getHeaderParameters().add(HTTPAuthorizationType.BEARER.toHTTPHeader(token.getTokenType(), token.getAccessToken()));
        hcc.setAuthorization(new HTTPAuthorization(HTTPAuthScheme.BEARER,token.getAccessToken()));
        PPAmountDAO amount = new PPAmountDAO();
        amount.setTotal(total);
        amount.setCurrency(currency);

        String json = GSONUtil.toJSONWrapper("amount", amount, true, false, false, null);
        hcc.setContent(SharedStringUtil.getBytes(json));

        System.out.println(GSONUtil.toJSON((NVEntity) hcc, true, false, false));
        HTTPCall hc = new HTTPCall(hcc, null);
        HTTPResponseData rd = hc.sendRequest();

        return GSONUtil.fromJSON(SharedStringUtil.toString(rd.getData()), PPRefundDAO.class);
    }


}
