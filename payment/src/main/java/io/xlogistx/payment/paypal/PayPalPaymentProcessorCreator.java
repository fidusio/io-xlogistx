package io.xlogistx.payment.paypal;

import org.zoxweb.shared.api.APIConfigInfo;
import org.zoxweb.shared.api.APIConfigInfoDAO;
import org.zoxweb.shared.api.APIDataStore;
import org.zoxweb.shared.api.APIException;
import org.zoxweb.shared.api.APIExceptionHandler;

import org.zoxweb.shared.api.APIServiceProviderCreator;
import org.zoxweb.shared.api.APIServiceType;
import org.zoxweb.shared.api.APITokenManager;
import org.zoxweb.shared.util.GetName;
import org.zoxweb.shared.util.NVPair;

public class PayPalPaymentProcessorCreator
        implements APIServiceProviderCreator {

    public enum Param
        implements GetName {

        API_NAME("PayPal"),
        API_KEY("api_key"),
        API_SECRET("api_secret"),

        ;

        private String name;

        Param(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }
    }


    @Override
    public APIConfigInfo createEmptyConfigInfo() {
        APIConfigInfoDAO configInfo = new APIConfigInfoDAO();
        configInfo.setAPITypeName(Param.API_NAME.getName());
        configInfo.setDescription("PayPal API configuration");
        configInfo.setVersion("1.0");
        configInfo.setOAuthVersion(APIConfigInfo.OAuthVersion.OAUTH_2);
        configInfo.setServiceTypes(new APIServiceType[]{APIServiceType.PAYMENT_PROCESSOR});
        configInfo.getConfigParameters().add(new NVPair(Param.API_KEY, (String) null));
        configInfo.getConfigParameters().add(new NVPair(Param.API_SECRET, (String) null));

        return configInfo;
    }

    @Override
    public APIExceptionHandler getExceptionHandler() {
        return null;
    }

    @Override
    public PayPalPaymentProcessor createAPI(APIDataStore<?> dataStore, APIConfigInfo apiConfig)
            throws APIException {
        PayPalPaymentProcessor payPalPaymentProcessor = new PayPalPaymentProcessor(apiConfig);

        return payPalPaymentProcessor;
    }

    @Override
    public String getName() {
        return Param.API_NAME.getName();
    }

    @Override
    public APITokenManager getAPITokenManager() {
        return null;
    }

}
