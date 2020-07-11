package io.xlogistx.payment.paypal.daos;

import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.util.GetNVConfig;
import org.zoxweb.shared.util.NVConfig;
import org.zoxweb.shared.util.NVConfigEntity;
import org.zoxweb.shared.util.NVConfigEntityLocal;
import org.zoxweb.shared.util.NVConfigManager;
import org.zoxweb.shared.util.SharedUtil;

@SuppressWarnings("serial")
public class PPPaymentOptionsDAO
	extends SetNameDescriptionDAO
{
	
	public enum Params
		implements GetNVConfig
	{
		ALLOWED_PAYMENT_METHOD(NVConfigManager.createNVConfig("allowed_payment_method", "Optional payment method type. If specified, the transaction will go through for only instant payment. ", "AllowedPaymentMethod", false, true, String.class)),
		
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
	
	public static final NVConfigEntity NVC_PAYPAL_PAYMENT_OPTIONS_DAO = new NVConfigEntityLocal(
																									"pp_payment_options_dao",
																									null,
																									"PPPaymentOptionsDAO", 
																									true, 
																									false, 
																									false, 
																									false, 
																									PPPaymentOptionsDAO.class, 
																									SharedUtil.extractNVConfigs(Params.values()), 
																									null, 
																									false, 
																									SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO
																								);
	
	public PPPaymentOptionsDAO()
	{
		super(NVC_PAYPAL_PAYMENT_OPTIONS_DAO);
	}
	
	public String getAllowedPaymentMethod() 
	{
		return lookupValue(Params.ALLOWED_PAYMENT_METHOD);
	}
	
	public void setAllowedPaymentMethod(String method) 
	{
		setValue(Params.ALLOWED_PAYMENT_METHOD, method);
	}

}