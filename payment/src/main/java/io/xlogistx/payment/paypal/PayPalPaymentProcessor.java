package io.xlogistx.payment.paypal;

import io.xlogistx.payment.paypal.daos.*;
import io.xlogistx.shared.data.OrderTransactionDAO;
import org.zoxweb.server.api.APIPaymentProcessor;
import org.zoxweb.server.util.DateUtil;
import org.zoxweb.shared.accounting.FinancialTransactionDAO;
import org.zoxweb.shared.api.APIConfigInfo;
import org.zoxweb.shared.api.APIException;
import org.zoxweb.shared.api.APIExceptionHandler;
import org.zoxweb.shared.api.APITokenDAO;
import org.zoxweb.shared.data.AddressDAO;
import org.zoxweb.shared.data.CreditCardDAO;
import org.zoxweb.shared.util.GetName;
import org.zoxweb.shared.util.SUS;

import java.io.IOException;


@SuppressWarnings("serial")
public class PayPalPaymentProcessor
    implements APIPaymentProcessor<APITokenDAO, APITokenDAO> {

    private static final String URL = "https://api.paypal.com";

    private APIConfigInfo configInfo;
    private volatile APITokenDAO apiTokenDAO;

    public PayPalPaymentProcessor(APIConfigInfo configInfo) {
        setAPIConfigInfo(configInfo);
    }

    public PayPalPaymentProcessor() {

    }


    @Override
    public APIConfigInfo getAPIConfigInfo() {
        return configInfo;
    }

    @Override
    public void setAPIConfigInfo(APIConfigInfo configInfo) {
        this.configInfo = configInfo;
    }

    @Override
    public synchronized APITokenDAO connect() throws APIException {

        if (apiTokenDAO == null) {
            apiTokenDAO = newConnection();
        }

        return apiTokenDAO;
    }

    @Override
    public APITokenDAO newConnection() throws APIException {
        try {
            return PayPalRestAPI.OAUTH2Token(URL,
                    configInfo.getProperties().getValue((GetName)PayPalPaymentProcessorCreator.Param.API_KEY),
                    configInfo.getProperties().getValue((GetName)PayPalPaymentProcessorCreator.Param.API_SECRET));
        } catch (IOException | InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            e.printStackTrace();
            throw new APIException(e.getMessage());
        }
    }

    @Override
    public void close() throws APIException {

    }

    @Override
    public boolean isProviderActive() {
        return false;
    }

    @Override
    public APIExceptionHandler getAPIExceptionHandler() {
        return null;
    }

    @Override
    public void setAPIExceptionHandler(APIExceptionHandler exceptionHandler) {

    }

    @Override
    public long lastTimeAccessed() {
        return 0;
    }

    @Override
    public long inactivityDuration() {
        return 0;
    }

    @Override
    public boolean isBusy() {
        return false;
    }

    @Override
    public <T> T lookupProperty(GetName propertyName) {
        return null;
    }

    @Override
    public String getAppID() {
        return null;
    }

    @Override
    public void setAppID(String appID) {

    }


    @Override
    public String toCanonicalID() {
        return null;
    }

    @Override
    public String getDomainID() {
        return null;
    }

    @Override
    public void setDomainID(String domainID) {

    }

    @Override
    public String getName() {
        return null;
    }

    @Override
    public void setDescription(String str) {

    }

    @Override
    public String getDescription() {
        return null;
    }

    @Override
    public void setName(String name) {

    }



    @Override
    public FinancialTransactionDAO createTransaction(FinancialTransactionDAO financialTransactionDAO) {
        SUS.checkIfNulls("Transaction is null.", financialTransactionDAO);

        OrderTransactionDAO orderTransactionDAO = null;

        if (financialTransactionDAO.getReferencedNVE() instanceof OrderTransactionDAO) {
            orderTransactionDAO = (OrderTransactionDAO) financialTransactionDAO.getReferencedNVE();
        }

        SUS.checkIfNulls("OrderTransactionDAO is missing.", orderTransactionDAO);

        CreditCardDAO creditCardDAO = orderTransactionDAO.getPaymentInfo().getCreditCard();
        AddressDAO addressDAO = orderTransactionDAO.getPaymentInfo().getBillingAddress();

        // Billing address
        PPAddressDAO billingAddress = new PPAddressDAO();
        billingAddress.setAddressLine1(addressDAO.getStreet());
        billingAddress.setCity(addressDAO.getCity());
        billingAddress.setState(addressDAO.getStateOrProvince());
        billingAddress.setPostalCode(addressDAO.getZIPOrPostalCode());
        billingAddress.setCountryCode(addressDAO.getCountry());

        // Credit Card
        PPCreditCardDAO cc = new PPCreditCardDAO();
        cc.setNumber(creditCardDAO.getCardNumber());
        cc.setType(creditCardDAO.getCardType().getDisplay());
        cc.setExpireMonth(DateUtil.getNormalizedMonth(creditCardDAO.getExpirationDate()));
        cc.setExpireYear(DateUtil.getNormalizedYear(creditCardDAO.getExpirationDate()));
        cc.setCardValidationCode(creditCardDAO.getSecurityCode());
        cc.setFirstName(creditCardDAO.getFirstName());
        cc.setLastName(creditCardDAO.getLastName());
        cc.setBillingAddress(billingAddress);

        // Amount
        PPAmountDAO amount = new PPAmountDAO();
        amount.setCurrency(financialTransactionDAO.getAmount().getCurrency().name());
        amount.setTotal(financialTransactionDAO.getAmount().getAmount().toString());

        // Transaction
        PPTransactionDAO transaction = new PPTransactionDAO();
        transaction.setAmount(amount);

        // Funding Instrument
        PPFundingInstrumentDAO fundingInstrument = new PPFundingInstrumentDAO();
        fundingInstrument.setCreditCard(cc);

        // Payer
        PPPayerDAO payer = new PPPayerDAO();
        payer.setPaymentMethod("credit_card");
        payer.getFundingInstruments().add(fundingInstrument);

        // Payment
        PPPaymentDAO payment = new PPPaymentDAO();
        payment.setIntent("sale");
        payment.setPayer(payer);
        payment.getTransactions().add(transaction);

        try {
            payment = PayPalRestAPI.payment(apiTokenDAO, URL, payment);
        } catch (IOException | InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            throw new APIException("Transaction creation failed: " + e.getMessage());
        }

        financialTransactionDAO.setExternalReference(payment.getID());

        return financialTransactionDAO;
    }

    @Override
    public FinancialTransactionDAO lookupTransaction(FinancialTransactionDAO financialTransactionDAO) {
        return null;
    }

    @Override
    public FinancialTransactionDAO updateTransaction(FinancialTransactionDAO financialTransactionDAO) {
        return null;
    }

    @Override
    public FinancialTransactionDAO cancelTransaction(FinancialTransactionDAO financialTransactionDAO) {
        return null;
    }

    @Override
    public FinancialTransactionDAO captureTransaction(FinancialTransactionDAO financialTransactionDAO) {
        return null;
    }

    @Override
    public FinancialTransactionDAO refundTransaction(FinancialTransactionDAO financialTransactionDAO) {
        SUS.checkIfNulls("Transaction is null.", financialTransactionDAO);
        SUS.checkIfNulls("External reference is null.", financialTransactionDAO.getExternalReference());
        SUS.checkIfNulls("Amount is null.", financialTransactionDAO.getAmount());

        PPRefundDAO refund = null;

        try {
            refund = PayPalRestAPI.refund(apiTokenDAO, URL,
                    financialTransactionDAO.getExternalReference(),
                    financialTransactionDAO.getAmount().getAmount().toString(),
                    financialTransactionDAO.getAmount().getCurrency().name());
        } catch (IOException | InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            throw new APIException("Transaction refund failed: " + e.getMessage());
        }

        financialTransactionDAO.setExternalReference(refund.getID());

        return financialTransactionDAO;
    }

}
