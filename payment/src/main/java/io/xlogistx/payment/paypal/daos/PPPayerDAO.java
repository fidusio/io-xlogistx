package io.xlogistx.payment.paypal.daos;

import java.util.List;

import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.util.ArrayValues;
import org.zoxweb.shared.util.GetNVConfig;
import org.zoxweb.shared.util.NVConfig;
import org.zoxweb.shared.util.NVConfigEntity;
import org.zoxweb.shared.util.NVConfigEntity.ArrayType;
import org.zoxweb.shared.util.NVConfigEntityLocal;
import org.zoxweb.shared.util.NVConfigManager;
import org.zoxweb.shared.util.SharedUtil;

@SuppressWarnings("serial")
public class PPPayerDAO
	extends SetNameDescriptionDAO
{
	public enum Params
		implements GetNVConfig
	{
		PAYMENT_METHOD(NVConfigManager.createNVConfig("payment_method", "Payment method used. Must be either credit_card or paypal.", "PaymentMethod", true, true, String.class)),
		FUNDING_INSTRUMENTS(NVConfigManager.createNVConfigEntity("funding_instruments", "A list of funding instruments for the current payment.", "FundingInstruments", true, true, PPFundingInstrumentDAO.NVC_PAYPAL_FUNDING_INSTRUMENT_DAO, ArrayType.LIST)),		
		PAYER_INFO(NVConfigManager.createNVConfigEntity("payer_info", "Information related to the payer.", "PayerInfo", true, true, PPPayerInfoDAO.NVC_PAYPAL_PAYER_INFO_DAO)),		
		STATUS(NVConfigManager.createNVConfig("status", "Status of the payer's PayPal account. Only supported when the payment_method is set to paypal. Allowed values: VERIFIED or UNVERIFIED.", "Status", true, true, String.class))
		
		;
		
		private final NVConfig cType;
		
		Params( NVConfig c)
		{
			cType = c;
		}
		
		public NVConfig getNVConfig() 
		{
			return cType;
		}
		
	}
	
	public static final NVConfigEntity NVC_PAYPAL_PAYER_DAO = new NVConfigEntityLocal(
																						"pp_payer_dao",
																						null,
																						"PPPayerDAO", 
																						true, 
																						false, 
																						false, 
																						false, 
																						PPPayerDAO.class, 
																						SharedUtil.extractNVConfigs(Params.values()), 
																						null, 
																						false, 
																						SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO
																					);
	
	public PPPayerDAO()
	{
		super(NVC_PAYPAL_PAYER_DAO);
	}
	
	public String getPaymentMethod() 
	{
		return lookupValue(Params.PAYMENT_METHOD);
	}
	
	public void setPaymentMethod(String method) 
	{
		setValue(Params.PAYMENT_METHOD, method);
	}
	
	@SuppressWarnings("unchecked")
	public ArrayValues<PPFundingInstrumentDAO> getFundingInstruments()
	{
		return (ArrayValues<PPFundingInstrumentDAO>) lookup(Params.FUNDING_INSTRUMENTS);
	}
	
	@SuppressWarnings("unchecked")
	public void setFundingInstruments(ArrayValues<PPFundingInstrumentDAO> values)
	{
		ArrayValues<PPFundingInstrumentDAO> content = (ArrayValues<PPFundingInstrumentDAO>) lookup(Params.FUNDING_INSTRUMENTS);
		content.add(values.values(), true);
	}
	
	@SuppressWarnings("unchecked")
	public void setFundingInstruments(List<PPFundingInstrumentDAO> values)
	{
		ArrayValues<PPFundingInstrumentDAO> content = (ArrayValues<PPFundingInstrumentDAO>) lookup(Params.FUNDING_INSTRUMENTS);
		content.add(values.toArray(new PPFundingInstrumentDAO[0]), true);
	}
	
	public PPPayerInfoDAO getPayerInfo() 
	{
		return lookupValue(Params.PAYER_INFO);
	}
	
	public void setPayerInfo(PPPayerInfoDAO info) 
	{
		setValue(Params.PAYER_INFO, info);
	}
	
	public String getStatus() 
	{
		return lookupValue(Params.STATUS);
	}
	
	public void setStatus(String status) 
	{
		setValue(Params.STATUS, status);
	}
}