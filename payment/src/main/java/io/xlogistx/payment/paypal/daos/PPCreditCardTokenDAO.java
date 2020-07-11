package io.xlogistx.payment.paypal.daos;

import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.util.GetNVConfig;
import org.zoxweb.shared.util.NVConfig;
import org.zoxweb.shared.util.NVConfigEntity;
import org.zoxweb.shared.util.NVConfigEntityLocal;
import org.zoxweb.shared.util.NVConfigManager;
import org.zoxweb.shared.util.SharedUtil;

@SuppressWarnings("serial")
public class PPCreditCardTokenDAO 
	extends SetNameDescriptionDAO
{
	
	public enum Params
		implements GetNVConfig
	{
		CREDIT_CARD_ID(NVConfigManager.createNVConfig("credit_card_id", "ID of credit card previously stored using /vault/credit-card.", "CreditCardID", true, true, String.class)),
		PAYER_ID(NVConfigManager.createNVConfig("payer_id", "A unique identifier that you can assign and track when storing a credit card or using a stored credit card. This ID can help to avoid unintentional use or misuse of credit cards. This ID can be any value you would like to associate with the saved card, such as a UUID, username, or email address.", "PayerID", true, true, String.class)),
		LAST_4(NVConfigManager.createNVConfig("last4", "Last four digits of the stored credit card number. Value assigned by PayPal.", "Last4", true, true, String.class)),
		TYPE(NVConfigManager.createNVConfig("type", "Credit card type. Valid types are: Visa, MasterCard, Discover, Amex. Values are presented in lowercase and not should not be used for display. Value assigned by PayPal.", "Type", true, true, String.class)),
		EXPIRE_YEAR(NVConfigManager.createNVConfig("expire_year", "4-digit expiration year. Value assigned by PayPal.", "ExpireYear", true, true, Integer.class)),
		EXPIRE_MONTH(NVConfigManager.createNVConfig("expire_month", "Expiration month with no leading zero. Acceptable values are 1 through 12. Value assigned by PayPal.", "ExpireMonth", true, true, Integer.class)),

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
	
	public static final NVConfigEntity NVC_PAYPAL_CREDIT_CARD_TOKEN_DAO = new NVConfigEntityLocal(
																									"pp_credit_card_token_dao",
																									null, 
																									"PPCreditCardTokenDAO", 
																									true, 
																									false, 
																									false, 
																									false, 
																									PPCreditCardTokenDAO.class, 
																									SharedUtil.extractNVConfigs(Params.values()), 
																									null, 
																									false, 
																									SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO
																								);
	
	public PPCreditCardTokenDAO()
	{
		super(NVC_PAYPAL_CREDIT_CARD_TOKEN_DAO);
	}
	
	public String getCreditCardID() 
	{
		return lookupValue(Params.CREDIT_CARD_ID);
	}
	
	public void setCreditCardID(String id) 
	{
		setValue(Params.CREDIT_CARD_ID, id);
	}
	
	public String getPayerID() 
	{
		return lookupValue(Params.PAYER_ID);
	}
	
	public void setPayerID(String id) 
	{
		setValue(Params.PAYER_ID, id);
	}
	
	public String getLastFour() 
	{
		return lookupValue(Params.LAST_4);
	}
	
	public void setLastFour(String last4) 
	{
		setValue(Params.LAST_4, last4);
	}
	
	public String getType() 
	{
		return lookupValue(Params.TYPE);
	}
	
	public void setType(String type) 
	{
		setValue(Params.TYPE, type);
	}
	
	public int getExpireYear() 
	{
		return lookupValue(Params.EXPIRE_YEAR);
	}
	
	public void setExpireYear(int year) 
	{
		setValue(Params.EXPIRE_YEAR, year);
	}
	
	public int getExpireMonth() 
	{
		return lookupValue(Params.EXPIRE_MONTH);
	}
	
	public void setExpireMonth(int month) 
	{
		setValue(Params.EXPIRE_MONTH, month);
	}
	
}