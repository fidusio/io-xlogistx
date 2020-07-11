package io.xlogistx.payment.paypal.daos;

import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.util.GetNVConfig;
import org.zoxweb.shared.util.NVConfig;
import org.zoxweb.shared.util.NVConfigEntity;
import org.zoxweb.shared.util.NVConfigEntityLocal;
import org.zoxweb.shared.util.NVConfigManager;
import org.zoxweb.shared.util.SharedUtil;

@SuppressWarnings("serial")
public class PPFMFDetailsDAO 
	extends SetNameDescriptionDAO
{
	
	public enum FilterType
	{
		ACCEPT,
		PENDING,
		DENY,
		REPORT,
		;
	}
	
	public enum FilterID
	{
		MAXIMUM_TRANSACTION_AMOUNT, 
		UNCONFIRMED_ADDRESS,
		COUNTRY_MONITOR,
		AVS_NO_MATCH,
		AVS_PARTIAL_MATCH,
		AVS_UNAVAILABLE_OR_UNSUPPORTED, 
		CARD_SECURITY_CODE_MISMATCH,
		BILLING_OR_SHIPPING_ADDRESS_MISMATCH,
		RISKY_ZIP_CODE,
		SUSPECTED_FREIGHT_FORWARDER_CHECK,
		RISKY_EMAIL_ADDRESS_DOMAIN_CHECK,
		RISKY_BANK_IDENTIFICATION_NUMBER_CHECK,
		RISKY_IP_ADDRESS_RANGE,
		LARGE_ORDER_NUMBER,
		TOTAL_PURCHASE_PRICE_MINIMUM,
		IP_ADDRESS_VELOCITY,
		PAYPAL_FRAUD_MODEL,
		
		;
	}
	
	public enum Params
		implements GetNVConfig
	{
		FILTER_TYPE(NVConfigManager.createNVConfig("filter_type", "Type of filter.", "FilterType", true, true, FilterType.class)),
		FILTER_ID(NVConfigManager.createNVConfig("filter_id", "Name of the fraud management filter.", "FilterID", true, true, FilterID.class)),
		
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
	
	public static final NVConfigEntity NVC_PAYPAL_FMF_DETAILS_DAO = new NVConfigEntityLocal(
																								"pp_fmf_details_dao",
																								null,
																								"PPFMFDetailsDAO", 
																								true, 
																								false, 
																								false, 
																								false, 
																								PPFMFDetailsDAO.class, 
																								SharedUtil.extractNVConfigs(Params.values()), 
																								null, 
																								false, 
																								SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO
																							);
	
	public PPFMFDetailsDAO()
	{
		super(NVC_PAYPAL_FMF_DETAILS_DAO);
	}
	
	public FilterType getFilterType() 
	{
		return lookupValue(Params.FILTER_TYPE);
	}
	
	public void setFilterType(FilterType type) 
	{
		setValue(Params.FILTER_TYPE, type);
	}
	
	public FilterID getFilterID() 
	{
		return lookupValue(Params.FILTER_ID);
	}
	
	public void setFilterID(FilterID id) 
	{
		setValue(Params.FILTER_ID, id);
	}

}