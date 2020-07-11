package io.xlogistx.payment.paypal.daos;

import java.util.List;

import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.util.ArrayValues;
import org.zoxweb.shared.util.GetNVConfig;
import org.zoxweb.shared.util.NVConfig;
import org.zoxweb.shared.util.NVConfigEntity;
import org.zoxweb.shared.util.NVConfigEntityLocal;
import org.zoxweb.shared.util.NVConfigManager;
import org.zoxweb.shared.util.SharedUtil;
import org.zoxweb.shared.util.NVConfigEntity.ArrayType;

@SuppressWarnings("serial")
public class PPItemListDAO 
	extends SetNameDescriptionDAO
{
	public enum Params
		implements GetNVConfig
	{
		ITEMS(NVConfigManager.createNVConfigEntity("items", "List of items.", "Items", true, true, PPItemDAO.NVC_ITEM_DAO, ArrayType.LIST)),		
		SHIPPING_ADDRESS(NVConfigManager.createNVConfigEntity("shipping_address", "Shipping address, if different than the payer address.", "ShippingAddress", false, true, PPAddressDAO.NVC_PAYPAL_ADDRESS_DAO)),		
		
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
	
	public static final NVConfigEntity NVC_PAYPAL_ITEM_LIST_DAO = new NVConfigEntityLocal(
																							"pp_item_list_dao",
																							null,
																							"PPItemListDAO", 
																							true, 
																							false, 
																							false, 
																							false, 
																							PPItemListDAO.class, 
																							SharedUtil.extractNVConfigs(Params.values()), 
																							null, 
																							false, 
																							SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO
																						);
	
	public PPItemListDAO()
	{
		super(NVC_PAYPAL_ITEM_LIST_DAO);
	}
	
	@SuppressWarnings("unchecked")
	public ArrayValues<PPItemDAO> getItems()
	{
		return (ArrayValues<PPItemDAO>) lookup(Params.ITEMS);
	}
	
	@SuppressWarnings("unchecked")
	public void setItems(ArrayValues<PPItemDAO> values)
	{
		ArrayValues<PPItemDAO> content = (ArrayValues<PPItemDAO>) lookup(Params.ITEMS);
		content.add(values.values(), true);
	}
	
	@SuppressWarnings("unchecked")
	public void setItems(List<PPItemDAO> values)
	{
		ArrayValues<PPItemDAO> content = (ArrayValues<PPItemDAO>) lookup(Params.ITEMS);
		content.add(values.toArray(new PPItemDAO[0]), true);
	}
	
	public PPAddressDAO getShippingAddress() 
	{
		return lookupValue(Params.SHIPPING_ADDRESS);
	}
	
	public void setShippingAddress(PPAddressDAO address) 
	{
		setValue(Params.SHIPPING_ADDRESS, address);
	}

}