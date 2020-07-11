package io.xlogistx.payment.paypal.daos;

import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.util.GetNVConfig;
import org.zoxweb.shared.util.NVConfig;
import org.zoxweb.shared.util.NVConfigEntity;
import org.zoxweb.shared.util.NVConfigEntityLocal;
import org.zoxweb.shared.util.NVConfigManager;
import org.zoxweb.shared.util.SharedUtil;

@SuppressWarnings("serial")
public class PPCurrencyDAO
	extends SetNameDescriptionDAO
{
	public enum Params
		implements GetNVConfig
	{
		CURRENCY(NVConfigManager.createNVConfig("currency", "3 letter currency code as defined by ISO 4217.", "Currency", true, true, String.class)),
		VALUE(NVConfigManager.createNVConfig("value", "Amount up to N digit after the decimals separator as defined in ISO 4217 for the appropriate currency code.", "Value", true, true, String.class)),
		
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
	
	public static final NVConfigEntity NVC_PAYPAL_CURRENCY_DAO = new NVConfigEntityLocal(
																							"pp_currency_dao",
																							null,
																							"PPCurrencyDAO", 
																							true, 
																							false, 
																							false, 
																							false, 
																							PPCurrencyDAO.class, 
																							SharedUtil.extractNVConfigs(Params.values()), 
																							null, 
																							false, 
																							SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO
																						);
	
	public PPCurrencyDAO()
	{
		super(NVC_PAYPAL_CURRENCY_DAO);
	}
	
	public String getCurrency() 
	{
		return lookupValue(Params.CURRENCY);
	}
	
	public void setCurrency(String currency) 
	{
		setValue(Params.CURRENCY, currency);
	}
	
	public String getValue() 
	{
		return lookupValue(Params.VALUE);
	}
	
	public void setValue(String value) 
	{
		setValue(Params.VALUE, value);
	}
	
}