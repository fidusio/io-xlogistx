package io.xlogistx.payment.paypal.daos;

import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.util.GetNVConfig;
import org.zoxweb.shared.util.NVConfig;
import org.zoxweb.shared.util.NVConfigEntity;
import org.zoxweb.shared.util.NVConfigEntityLocal;
import org.zoxweb.shared.util.NVConfigManager;
import org.zoxweb.shared.util.SharedUtil;

@SuppressWarnings("serial")
public class PPFundingInstrumentDAO 
	extends SetNameDescriptionDAO
{
	public enum Params
		implements GetNVConfig
	{
		CREDIT_CARD(NVConfigManager.createNVConfigEntity("credit_card", "Credit card details.", "CreditCard", true, true, PPCreditCardDAO.NVC_PAYPAL_CREDIT_CARD_DAO)),		
		CREDIT_CARD_TOKEN(NVConfigManager.createNVConfigEntity("credit_card_token", "Token for credit card details stored with PayPal. You can use this in place of a credit card.", "CreditCardToken", true, true, PPCreditCardTokenDAO.NVC_PAYPAL_CREDIT_CARD_TOKEN_DAO)),		
		
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

	public static final NVConfigEntity NVC_PAYPAL_FUNDING_INSTRUMENT_DAO = new NVConfigEntityLocal(
																										"pp_funding_instrument_dao",
																										null, 
																										"PPFundingInstrumentDAO", 
																										true, 
																										false, 
																										false, 
																										false, 
																										PPFundingInstrumentDAO.class, 
																										SharedUtil.extractNVConfigs(Params.values()), 
																										null, 
																										false, 
																										SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO
																									);
	
	public PPFundingInstrumentDAO()
	{
		super(NVC_PAYPAL_FUNDING_INSTRUMENT_DAO);
	}
	
	public PPCreditCardDAO getCreditCard() 
	{
		return lookupValue(Params.CREDIT_CARD);
	}
	
	public void setCreditCard(PPCreditCardDAO card) 
	{
		setValue(Params.CREDIT_CARD, card);
	}
	
	public PPCreditCardTokenDAO getCreditCardToken() 
	{
		return lookupValue(Params.CREDIT_CARD_TOKEN);
	}
	
	public void setCreditCardToken(PPCreditCardTokenDAO token) 
	{
		setValue(Params.CREDIT_CARD_TOKEN, token);
	}
	
}