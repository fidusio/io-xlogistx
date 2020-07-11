package io.xlogistx.payment.paypal.daos;

import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.util.GetNVConfig;
import org.zoxweb.shared.util.NVConfig;
import org.zoxweb.shared.util.NVConfigEntity;
import org.zoxweb.shared.util.NVConfigEntityLocal;
import org.zoxweb.shared.util.NVConfigManager;
import org.zoxweb.shared.util.SharedUtil;

@SuppressWarnings("serial")
public class PPPayerInfoDAO
	extends SetNameDescriptionDAO
{
	public enum Params
		implements GetNVConfig
	{
		EMAIL(NVConfigManager.createNVConfig("email", "Email address representing the payer. 127 characters max.", "Email", true, true, String.class)),
		SALUTATION(NVConfigManager.createNVConfig("salutation", "Salutation of the payer.", "Salutation", true, true, String.class)),
		FIRST_NAME(NVConfigManager.createNVConfig("first_name", "First name of the payer. Value assigned by PayPal.", "FirstName", true, true, String.class)),
		MIDDLE_NAME(NVConfigManager.createNVConfig("middle_name", "Middle name of the payer Value assigned by PayPal.", "MiddleName", true, true, String.class)),
		LAST_NAME(NVConfigManager.createNVConfig("last_name", "Last name of the payer. Value assigned by PayPal.", "LastName", true, true, String.class)),
		SUFFIX(NVConfigManager.createNVConfig("suffix", "Suffix of the payer.", "Suffix", false, true, String.class)),
		PAYER_ID(NVConfigManager.createNVConfig("payer_id", "PayPal assigned Payer ID. Value assigned by PayPal.", "PayerID", true, true, String.class)),
		PHONE(NVConfigManager.createNVConfig("phone", "Phone number representing the payer. 20 characters max.", "Phone", true, true, String.class)),
		COUNTRY_CODE(NVConfigManager.createNVConfig("country_code", "Two-letter registered country code of the payer to identify the buyer country.", "CountryCode", true, true, String.class)),
		SHIPPING_ADDRESS(NVConfigManager.createNVConfigEntity("shipping_address", "Shipping address of payer PayPal account. Value assigned by PayPal.", "ShippingAddress", true, true, PPAddressDAO.NVC_PAYPAL_ADDRESS_DAO)),		
		TAX_ID_TYPE(NVConfigManager.createNVConfig("tax_id_type", "Payer's tax ID type. Allowed values: BR_CPF or BR_CNPJ. Only supported when the payment_method is set to paypal.", "TaxIDType", true, true, String.class)),
		TAX_ID(NVConfigManager.createNVConfig("tax_id", "Payer�s tax ID. Only supported when the payment_method is set to paypal.", "TaxID", true, true, String.class)),
		
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
	
	public static final NVConfigEntity NVC_PAYPAL_PAYER_INFO_DAO = new NVConfigEntityLocal(
																								"pp_payer_info_dao",
																								null, 
																								"PPPayerInfoDAO", 
																								true, 
																								false, 
																								false, 
																								false, 
																								PPPayerInfoDAO.class, 
																								SharedUtil.extractNVConfigs(Params.values()), 
																								null, 
																								false, 
																								SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO
																							);
	
	public PPPayerInfoDAO()
	{
		super(NVC_PAYPAL_PAYER_INFO_DAO);
	}
	
	public String getEmail() 
	{
		return lookupValue(Params.EMAIL);
	}
	
	public void setEmail(String email) 
	{
		setValue(Params.EMAIL, email);
	}
	
	public String getSalutation() 
	{
		return lookupValue(Params.SALUTATION);
	}
	
	public void setSalutation(String salutation) 
	{
		setValue(Params.SALUTATION, salutation);
	}
	
	public String getFirstName() 
	{
		return lookupValue(Params.FIRST_NAME);
	}
	
	public void setFirstName(String firstName) 
	{
		setValue(Params.FIRST_NAME, firstName);
	}
	
	public String getMiddleName() 
	{
		return lookupValue(Params.MIDDLE_NAME);
	}
	
	public void setMiddleName(String middleName) 
	{
		setValue(Params.MIDDLE_NAME, middleName);
	}
	
	public String getLastName() 
	{
		return lookupValue(Params.LAST_NAME);
	}
	
	public void setLastName(String lastName) 
	{
		setValue(Params.LAST_NAME, lastName);
	}

	public String getSuffix() 
	{
		return lookupValue(Params.SUFFIX);
	}
	
	public void setSuffix(String suffix) 
	{
		setValue(Params.SUFFIX, suffix);
	}
	
	public String getPayerID() 
	{
		return lookupValue(Params.PAYER_ID);
	}
	
	public void setPayerID(String id) 
	{
		setValue(Params.PAYER_ID, id);
	}
	
	public String getPhone() 
	{
		return lookupValue(Params.PHONE);
	}
	
	public void setPhone(String phone) 
	{
		setValue(Params.PHONE, phone);
	}
	
	public String getCountryCode() 
	{
		return lookupValue(Params.COUNTRY_CODE);
	}
	
	public void setCountryCode(String countryCode) 
	{
		setValue(Params.COUNTRY_CODE, countryCode);
	}
	
	public PPAddressDAO getShippingAddress() 
	{
		return lookupValue(Params.SHIPPING_ADDRESS);
	}
	
	public void setShippingAddress(PPAddressDAO address) 
	{
		setValue(Params.SHIPPING_ADDRESS, address);
	}
	
	public String getTaxIDType() 
	{
		return lookupValue(Params.TAX_ID_TYPE);
	}
	
	public void setTaxIDType(String type) 
	{
		setValue(Params.TAX_ID_TYPE, type);
	}
	
	public String getTaxID() 
	{
		return lookupValue(Params.TAX_ID);
	}
	
	public void setTaxID(String id) 
	{
		setValue(Params.TAX_ID, id);
	}
	
}