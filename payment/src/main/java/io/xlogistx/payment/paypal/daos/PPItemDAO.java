package io.xlogistx.payment.paypal.daos;

import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.util.GetNVConfig;
import org.zoxweb.shared.util.NVConfig;
import org.zoxweb.shared.util.NVConfigEntity;
import org.zoxweb.shared.util.NVConfigEntityLocal;
import org.zoxweb.shared.util.NVConfigManager;
import org.zoxweb.shared.util.SharedUtil;

@SuppressWarnings("serial")
public class PPItemDAO 
	extends SetNameDescriptionDAO
{
	public enum Params
		implements GetNVConfig
	{
		QUANTITY(NVConfigManager.createNVConfig("quantity", "Number of a particular item. 10 characters max.", "Quantity", true, true, String.class)),
		NAME(NVConfigManager.createNVConfig("name", "Item name. 127 characters max.", "Name", true, true, String.class)),
		PRICE(NVConfigManager.createNVConfig("price", "Item cost. 10 characters max.", "Price", true, true, String.class)),
		CURRENCY(NVConfigManager.createNVConfig("currency", "3-letter currency code.", "Currency", true, true, String.class)),
		SKU(NVConfigManager.createNVConfig("sku", "Stock keeping unit corresponding (SKU) to item. 50 characters max.", "SKU", true, true, String.class)),
		DESCRIPTION(NVConfigManager.createNVConfig("description", "Description of the item.", "Description", true, true, String.class)),
		TAX(NVConfigManager.createNVConfig("tax", "Tax of the item.", "Tax", true, true, String.class)),
		
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
	
	public static final NVConfigEntity NVC_ITEM_DAO = new NVConfigEntityLocal(
																				"pp_item_dao",
																				null,
																				"PPItemDAO", 
																				true, 
																				false, 
																				false, 
																				false, 
																				PPItemDAO.class, 
																				SharedUtil.extractNVConfigs(Params.values()), 
																				null, 
																				false, 
																				SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO
																			 );
	
	public PPItemDAO()
	{
		super(NVC_ITEM_DAO);
	}
	
	public String getQuantity() 
	{
		return lookupValue(Params.QUANTITY);
	}
	
	public void setQuantity(String quantity) 
	{
		setValue(Params.QUANTITY, quantity);
	}
	
	public String getName() 
	{
		return lookupValue(Params.NAME);
	}
	
	public void setName(String name) 
	{
		setValue(Params.NAME, name);
	}
	
	public String getPrice() 
	{
		return lookupValue(Params.PRICE);
	}
	
	public void setPrice(String price) 
	{
		setValue(Params.PRICE, price);
	}
	
	public String getCurrency() 
	{
		return lookupValue(Params.CURRENCY);
	}
	
	public void setCurrency(String currency) 
	{
		setValue(Params.CURRENCY, currency);
	}
	
	public String getSku() 
	{
		return lookupValue(Params.SKU);
	}
	
	public void setSku(String sku) 
	{
		setValue(Params.SKU, sku);
	}
	
	public String getDescription() 
	{
		return lookupValue(Params.DESCRIPTION);
	}
	
	public void setDescription(String description) 
	{
		setValue(Params.DESCRIPTION, description);
	}
	
	public String getTax()
	{
		return lookupValue(Params.TAX);
	}
	
	public void setTax(String tax) 
	{
		setValue(Params.TAX, tax);
	}
	
}