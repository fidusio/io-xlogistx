package io.xlogistx.payment.paypal.daos;

import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.util.ArrayValues;
import org.zoxweb.shared.util.GetNVConfig;
import org.zoxweb.shared.util.NVConfig;
import org.zoxweb.shared.util.NVConfigEntity;
import org.zoxweb.shared.util.NVConfigEntity.ArrayType;
import org.zoxweb.shared.util.NVConfigEntityLocal;
import org.zoxweb.shared.util.NVConfigManager;
import org.zoxweb.shared.util.NVEntity;
import org.zoxweb.shared.util.SharedUtil;

@SuppressWarnings("serial")
public class PPTransactionDAO
	extends SetNameDescriptionDAO
{
	
	public enum Params
		implements GetNVConfig
	{
		AMOUNT(NVConfigManager.createNVConfigEntity("amount", "Amoung being collected.", "Amount", true, true, PPAmountDAO.NVC_PAYPAL_AMOUNT_DAO)),
		DESCRIPTION(NVConfigManager.createNVConfig("description", "Description of transaction. 127 characters max.", "Description", false, true, String.class)),
		ITEM_LIST(NVConfigManager.createNVConfigEntity("item_list", "Items and related shipping address within a transaction.", "ItemList", false, true, PPItemListDAO.NVC_PAYPAL_ITEM_LIST_DAO)),
		RELATED_RESOURCES(NVConfigManager.createNVConfigEntity("related_resources", "Financial transactions related to a payment.", "RelatedResources", false, true, PPComboResourceDAO.NVC_COMBO_RESOURCE_DAO, ArrayType.LIST)),
		INVOICE_NUMBER(NVConfigManager.createNVConfig("invoice_number", "Invoice number used to track the payment. Only supported when the payment_method is set to paypal. 256 characters max.", "InvoiceNumber", false, true, String.class)),
		CUSTOM(NVConfigManager.createNVConfig("custom", "Free-form field for the use of clients. Only supported when the payment_method is set to paypal. 256 characters max.", "Custom", false, true, String.class)),
		SOFT_DESCRIPTOR(NVConfigManager.createNVConfig("soft_descriptor", "Soft descriptor used when charging this funding source. Only supported when the payment_method is set to paypal. 22 characters max.", "SoftDescriptor", false, true, String.class)),
		PAYMENT_OPTIONS(NVConfigManager.createNVConfigEntity("payment_options", "Payment options requested for this purchase unit.", "Amount", true, true, PPPaymentOptionsDAO.NVC_PAYPAL_PAYMENT_OPTIONS_DAO)),

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
	
	public static final NVConfigEntity NVC_PAYPAL_TRANSACTION_DAO = new NVConfigEntityLocal(
																								"pp_transaction_dao",
																								null,
																								"PPTransactionDAO", 
																								true, 
																								false, 
																								false, 
																								false, 
																								PPTransactionDAO.class, 
																								SharedUtil.extractNVConfigs(Params.values()), 
																								null, 
																								false, 
																								SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO
																							);
	
	public PPTransactionDAO()
	{
		super(NVC_PAYPAL_TRANSACTION_DAO);
	}
	
	public PPAmountDAO getAmount()
	{
		return lookupValue(Params.AMOUNT);
	}
	
	public void setAmount(PPAmountDAO amount)
	{
		setValue(Params.AMOUNT, amount);
	}
	
	public PPItemListDAO getItemList()
	{
		return lookupValue(Params.ITEM_LIST);
	}
	
	public void setItemList(PPItemListDAO list)
	{
		setValue(Params.ITEM_LIST, list);
	}
	
	@SuppressWarnings("unchecked")
	public ArrayValues<NVEntity> getRelatedResources()
	{
		return (ArrayValues<NVEntity>) lookup(Params.RELATED_RESOURCES);
	}
	
//	@SuppressWarnings("unchecked")
//	public void setRelatedResources(ArrayValues<NVEntity> values)
//	{
//		ArrayValues<NVEntity> content = (ArrayValues<NVEntity>) lookup(Params.RELATED_RESOURCES);
//		content.add(values.values(), true);
//	}
//	
//	@SuppressWarnings("unchecked")
//	public void setRelatedResources(List<NVEntity> values)
//	{
//		ArrayValues<NVEntity> content = (ArrayValues<NVEntity>) lookup(Params.RELATED_RESOURCES);
//		content.add(values.toArray(new NVEntity[0]), true);
//	}

	public String getInvoiceNumber()
	{
		return lookupValue(Params.INVOICE_NUMBER);
	}
	
	public void setInvoiceNumber(String number)
	{
		setValue(Params.INVOICE_NUMBER, number);
	}
	
	public String getCustom()
	{
		return lookupValue(Params.CUSTOM);
	}
	
	public void setCustom(String custom)
	{
		setValue(Params.CUSTOM, custom);
	}
	
	public String getSoftDescriptor()
	{
		return lookupValue(Params.SOFT_DESCRIPTOR);
	}
	
	public void setSoftDescriptor(String descriptor)
	{
		setValue(Params.SOFT_DESCRIPTOR, descriptor);
	}
	
	public PPPaymentOptionsDAO getPaymentOptions()
	{
		return lookupValue(Params.PAYMENT_OPTIONS);
	}
	
	public void setPaymentOptions(PPPaymentOptionsDAO options)
	{
		setValue(Params.PAYMENT_OPTIONS, options);
	}
	
}