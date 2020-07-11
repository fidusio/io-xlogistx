package io.xlogistx.payment.paypal.daos;

import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.util.GetNVConfig;
import org.zoxweb.shared.util.NVConfig;
import org.zoxweb.shared.util.NVConfigEntity;
import org.zoxweb.shared.util.NVConfigEntityLocal;
import org.zoxweb.shared.util.NVConfigManager;
import org.zoxweb.shared.util.SharedUtil;

@SuppressWarnings("serial")
public class PPDetailsDAO
	extends SetNameDescriptionDAO
{
	
	public enum Params
		implements GetNVConfig
	{
		SHIPPING(NVConfigManager.createNVConfig("shipping", "Amount charged for shipping. 10 characters max with support for 2 decimal places.", "Shipping", true, true, String.class)),
		SUBTOTAL(NVConfigManager.createNVConfig("subtotal", "Amount of the subtotal of the items. Required if line items are specified. 10 characters max, with support for 2 decimal places.", "Subtotal", true, true, String.class)),
		TAX(NVConfigManager.createNVConfig("tax", "Amount charged for tax. 10 characters max with support for 2 decimal places.", "Tax", true, true, String.class)),
		HANDLING_FEE(NVConfigManager.createNVConfig("handling_fee", "Amount being charged for the handling fee. Only supported when the payment_method is set to paypal.", "HandlingFee", true, true, String.class)),
		INSURANCE(NVConfigManager.createNVConfig("insurance", "Amount being charged for the insurance fee. Only supported when the payment_method is set to paypal.", "Insurance", true, true, String.class)),
		SHIPPING_DISCOUNT(NVConfigManager.createNVConfig("shipping_discount", "Amount being discounted for the shipping fee. Only supported when the payment_method is set to paypal.", "ShippingDiscount", true, true, String.class)),

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
	
	public static final NVConfigEntity NVC_PAYPAL_DETAILS_DAO = new NVConfigEntityLocal(
																							"pp_details_dao",
																							null,
																							"PPDetailsDAO", 
																							true, 
																							false, 
																							false, 
																							false, 
																							PPDetailsDAO.class, 
																							SharedUtil.extractNVConfigs(Params.values()), 
																							null, 
																							false, 
																							SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO
																						);
	
	public PPDetailsDAO()
	{
		super(NVC_PAYPAL_DETAILS_DAO);
	}
	
	public String getShipping() 
	{
		return lookupValue(Params.SHIPPING);
	}
	
	public void setShipping(String shipping) 
	{
		setValue(Params.SHIPPING, shipping);
	}
	
	public String getSubtotal() 
	{
		return lookupValue(Params.SUBTOTAL);
	}
	
	public void setSubtotal(String subtotal) 
	{
		setValue(Params.SUBTOTAL, subtotal);
	}
	
	public String getTax() 
	{
		return lookupValue(Params.TAX);
	}
	
	public void setTax(String tax) 
	{
		setValue(Params.TAX, tax);
	}
	
	public String getHandlingFee() 
	{
		return lookupValue(Params.HANDLING_FEE);
	}
	
	public void setHandlingFee(String fee) 
	{
		setValue(Params.HANDLING_FEE, fee);
	}
	
	public String getInsurance() 
	{
		return lookupValue(Params.INSURANCE);
	}
	
	public void setInsurance(String insurance) 
	{
		setValue(Params.INSURANCE, insurance);
	}
	
	public String getShippingDiscount() 
	{
		return lookupValue(Params.SHIPPING_DISCOUNT);
	}
	
	public void setShippingDiscount(String discount) 
	{
		setValue(Params.SHIPPING_DISCOUNT, discount);
	}
	
}