package io.xlogistx.payment.paypal.daos;

import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.util.GetNVConfig;
import org.zoxweb.shared.util.NVConfig;
import org.zoxweb.shared.util.NVConfigEntity;
import org.zoxweb.shared.util.NVConfigEntityLocal;
import org.zoxweb.shared.util.NVConfigManager;
import org.zoxweb.shared.util.SharedUtil;

@SuppressWarnings("serial")
public class PPAddressDAO 
	extends SetNameDescriptionDAO
{
	
	public enum Params
		implements GetNVConfig
	{
		RECIPIENT_NAME(NVConfigManager.createNVConfig("recipient_name", "Name of the recipient at this address. 50 characters max.", "RecipientName", true, true, String.class)),
		TYPE(NVConfigManager.createNVConfig("type", "Address type. Must be one of the following: residential, business, or mailbox.", "Type", false, true, String.class)),
		LINE_1(NVConfigManager.createNVConfig("line1", "Line 1 of the address (e.g., Number, street, etc). 100 characters max.", "AddressLine1", true, true, String.class)),
		LINE_2(NVConfigManager.createNVConfig("line2", "Line 2 of the address (e.g., Suite, apt #, etc). 100 characters max.", "AddressLine2", false, true, String.class)),
		CITY(NVConfigManager.createNVConfig("city", "City name. 50 characters max.", "City", true, true, String.class)),
		COUNTRY_CODE(NVConfigManager.createNVConfig("country_code", "2-letter country code. 2 characters max.", "CountryCode", true, true, String.class)),
		POSTAL_CODE(NVConfigManager.createNVConfig("postal_code", "Zip code or equivalent is usually required for countries that have them. 20 characters max.", "PostalCode", true, true, String.class)),
		STATE(NVConfigManager.createNVConfig("state", "Zip code or equivalent is usually required for countries that have them. 20 characters max.", "State", false, true, String.class)),
		PHONE(NVConfigManager.createNVConfig("phone", "Phone number in E.123 format. 50 characters max.", "PhoneNumber", false, true, String.class)),
		
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

	public static final NVConfigEntity NVC_PAYPAL_ADDRESS_DAO = new NVConfigEntityLocal(
																							"pp_address_dao",
																							null, 
																							"PPAddressDAO", 
																							true, 
																							false, 
																							false, 
																							false, 
																							PPAddressDAO.class, 
																							SharedUtil.extractNVConfigs(Params.values()), 
																							null, 
																							false, 
																							SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO
																						);

	public PPAddressDAO()
	{
		super(NVC_PAYPAL_ADDRESS_DAO);
	}
	
	public String getRecipientName() 
	{
		return lookupValue(Params.RECIPIENT_NAME);
	}
	
	public void setRecipientName(String name) 
	{
		setValue(Params.RECIPIENT_NAME, name);
	}
	
	public String getType() 
	{
		return lookupValue(Params.TYPE);
	}
	
	public void setType(String type) 
	{
		setValue(Params.TYPE, type);
	}
	
	public String getAddressLine1() 
	{
		return lookupValue(Params.LINE_1);
	}
	
	public void setAddressLine1(String line1) 
	{
		setValue(Params.LINE_1, line1);
	}
	
	public String getAddressLine2() 
	{
		return lookupValue(Params.LINE_2);
	}
	
	public void setAddressLine2(String line2) 
	{
		setValue(Params.LINE_2, line2);
	}
	
	public String getCity() 
	{
		return lookupValue(Params.CITY);
	}
	
	public void setCity(String city) 
	{
		setValue(Params.CITY, city);
	}
	
	public String getCountryCode() 
	{
		return lookupValue(Params.COUNTRY_CODE);
	}
	
	public void setCountryCode(String countryCode)
	{
		setValue(Params.COUNTRY_CODE, countryCode);
	}
	
	public String getPostalCode() 
	{
		return lookupValue(Params.POSTAL_CODE);
	}
	
	public void setPostalCode(String postalCode)
	{
		setValue(Params.POSTAL_CODE, postalCode);
	}
	
	public String getState() 
	{
		return lookupValue(Params.STATE);
	}
	
	public void setState(String state)
	{
		setValue(Params.STATE, state);
	}
	
	public String getPhone() 
	{
		return lookupValue(Params.PHONE);
	}
	
	public void setPhone(String phone)
	{
		setValue(Params.PHONE, phone);
	}
	
}