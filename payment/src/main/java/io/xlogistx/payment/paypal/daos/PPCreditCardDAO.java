package io.xlogistx.payment.paypal.daos;

import java.util.Date;

import org.zoxweb.server.filters.DateTimeValueFilter;
import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.util.GetNVConfig;
import org.zoxweb.shared.util.NVConfig;
import org.zoxweb.shared.util.NVConfigEntity;
import org.zoxweb.shared.util.NVConfigEntityLocal;
import org.zoxweb.shared.util.NVConfigManager;
import org.zoxweb.shared.util.SharedUtil;

@SuppressWarnings("serial")
public class PPCreditCardDAO
	extends SetNameDescriptionDAO
{
	
	public enum Params
		implements GetNVConfig
	{
		ID(NVConfigManager.createNVConfig("id", "ID of the credit card. This ID is provided in the response when storing credit cards.", "ID", true, true, String.class)),
		PAYER_ID(NVConfigManager.createNVConfig("payer_id", "A unique identifier that you can assign and track when storing a credit card or using a stored credit card. This ID can help to avoid unintentional use or misuse of credit cards. This ID can be any value you would like to associate with the saved card, such as a UUID, username, or email address.", "PayerID", true, true, String.class)),
		NUMBER(NVConfigManager.createNVConfig("number", "Credit card number. Numeric characters only with no spaces or punctuation. The string must conform with modulo and length required by each credit card type.", "Number", true, true, String.class)),
		TYPE(NVConfigManager.createNVConfig("type", "Credit card type. Valid types are: Visa, MasterCard, Discover, Amex.", "Type", true, true, String.class)),
		EXPIRE_MONTH(NVConfigManager.createNVConfig("expire_month", "Expiration month with no leading zero. Acceptable values are 1 through 12.", "ExpireMonth", true, true, Integer.class)),
		EXPIRE_YEAR(NVConfigManager.createNVConfig("expire_year", "4-digit expiration year.", "ExpireYear", true, true, Integer.class)),
		CVV2(NVConfigManager.createNVConfig("cvv2", "3-4 digit card validation code.", "CardValidationCode", true, true, String.class)),
		FIRST_NAME(NVConfigManager.createNVConfig("first_name", "Cardholder�s first name.", "FirstName", true, true, String.class)),
		LAST_NAME(NVConfigManager.createNVConfig("last_name", "Cardholder�s last name.", "LastName", true, true, String.class)),
		BILLING_ADDRESS(NVConfigManager.createNVConfigEntity("billing_address", "Billing address associated with card.", "BillingAddress", true, true, PPAddressDAO.NVC_PAYPAL_ADDRESS_DAO)),
		EXTERNAL_CUSTOMER_ID(NVConfigManager.createNVConfig("external_customer_id", "A unique identifier of the customer to whom this bank account belongs. Generated and provided by the facilitator.", "ExternalCustomerID", true, true, String.class)),
		MERCHANT_ID(NVConfigManager.createNVConfig("merchant_id", "A user-provided, optional field that functions as a unique identifier for the merchant holding the card. Note that this has no relation to PayPal merchant id.", "MerchantID", true, true, String.class)),
		EXTERNAL_CARD_ID(NVConfigManager.createNVConfig("external_card_id", "A unique identifier of the bank account resource. Generated and provided by the facilitator so it can be used to restrict the usage of the bank account to the specific merchant.", "ExternalCardID", true, true, String.class)),
		CREATE_TIME(NVConfigManager.createNVConfig("create_time", "Resource creation time in ISO8601 date-time format (ex: 1994-11-05T13:15:30Z).", "CreationTime", true, true,false, Date.class, new DateTimeValueFilter("yyyy-MM-dd'T'HH:mm:ss'Z'", "UTC"))),
		UPDATE_TIME(NVConfigManager.createNVConfig("update_time", "Resource update time in ISO8601 date-time format (ex: 1994-11-05T13:15:30Z).", "UpdateTime", true, true, false, Date.class, new DateTimeValueFilter("yyyy-MM-dd'T'HH:mm:ss'Z'", "UTC"))),
		STATE(NVConfigManager.createNVConfig("state", "State of the credit card funding instrument: expired or ok. Value assigned by PayPal.", "State", true, true, String.class)),
		VALID_UNTIL(NVConfigManager.createNVConfig("valid_until", "Funding instrument expiration date. Value assigned by PayPal.", "ValidUntilDate", true, true, String.class)),

		;
		
		private final NVConfig cType;
		
		Params(NVConfig c)
		{
			cType = c;
		}
		
		public NVConfig getNVConfig() 
		{
			return cType;
		}
	}

	public static final NVConfigEntity NVC_PAYPAL_CREDIT_CARD_DAO = new NVConfigEntityLocal(
																								"pp_credit_card_dao",
																								null, 
																								"PPCreditCardDAO", 
																								true, 
																								false, 
																								false, 
																								false, 
																								PPCreditCardDAO.class, 
																								SharedUtil.extractNVConfigs(Params.values()), 
																								null, 
																								false, 
																								SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO
																							);
	
	public PPCreditCardDAO()
	{
		super(NVC_PAYPAL_CREDIT_CARD_DAO);
	}
	
	public String getID() 
	{
		return lookupValue(Params.ID);
	}
	
	public void setID(String id) 
	{
		setValue(Params.ID, id);
	}
	
	public String getPayerID() 
	{
		return lookupValue(Params.PAYER_ID);
	}
	
	public void setPayerID(String id) 
	{
		setValue(Params.PAYER_ID, id);
	}
	
	public String getNumber() 
	{
		return lookupValue(Params.NUMBER);
	}
	
	public void setNumber(String number) 
	{
		setValue(Params.NUMBER, number);
	}
	
	public String getType() 
	{
		return lookupValue(Params.TYPE);
	}
	
	public void setType(String type) 
	{
		setValue(Params.TYPE, type);
	}
	
	public int getExpireMonth() 
	{
		return lookupValue(Params.EXPIRE_MONTH);
	}
	
	public void setExpireMonth(int month) 
	{
		setValue(Params.EXPIRE_MONTH, month);
	}
	
	public int getExpireYear() 
	{
		return lookupValue(Params.EXPIRE_YEAR);
	}
	
	public void setExpireYear(int year) 
	{
		setValue(Params.EXPIRE_YEAR, year);
	}
	
	public String getCardValidationCode() 
	{
		return lookupValue(Params.CVV2);
	}
	
	public void setCardValidationCode(String cvv2) 
	{
		setValue(Params.CVV2, cvv2);
	}
	
	public String getFirstName() 
	{
		return lookupValue(Params.FIRST_NAME);
	}
	
	public void setFirstName(String firstName) 
	{
		setValue(Params.FIRST_NAME, firstName);
	}
	
	public String getLastName() 
	{
		return lookupValue(Params.LAST_NAME);
	}
	
	public void setLastName(String lastName) 
	{
		setValue(Params.LAST_NAME, lastName);
	}
	
	public PPAddressDAO getBillingAddress() 
	{
		return lookupValue(Params.BILLING_ADDRESS);
	}
	
	public void setBillingAddress(PPAddressDAO address) 
	{
		setValue(Params.BILLING_ADDRESS, address);
	}
	
	public String getExternalCustomerID() 
	{
		return lookupValue(Params.EXTERNAL_CUSTOMER_ID);
	}
	
	public void setExternalCustomerID(String id) 
	{
		setValue(Params.EXTERNAL_CUSTOMER_ID, id);
	}
	
	public String getMerchantID() 
	{
		return lookupValue(Params.MERCHANT_ID);
	}
	
	public void setMerchantID(String id) 
	{
		setValue(Params.MERCHANT_ID, id);
	}
	
	public String getExternalCardID() 
	{
		return lookupValue(Params.EXTERNAL_CARD_ID);
	}
	
	public void setExternalCardID(String id) 
	{
		setValue(Params.EXTERNAL_CARD_ID, id);
	}
	
	public long getCreateTime() 
	{
		return lookupValue(Params.CREATE_TIME);
	}
	
	public void setCreateTime(long time) 
	{
		setValue(Params.CREATE_TIME, time);
	}
	
	public long getUpdateTime() 
	{
		return lookupValue(Params.UPDATE_TIME);
	}
	
	public void setUpdateTime(long time) 
	{
		setValue(Params.UPDATE_TIME, time);
	}
	
	public String getState() 
	{
		return lookupValue(Params.STATE);
	}
	
	public void setState(String state) 
	{
		setValue(Params.STATE, state);
	}
	
	public String getValidUntil() 
	{
		return lookupValue(Params.VALID_UNTIL);
	}
	
	public void setValidUntil(String date) 
	{
		setValue(Params.VALID_UNTIL, date);
	}
	
}