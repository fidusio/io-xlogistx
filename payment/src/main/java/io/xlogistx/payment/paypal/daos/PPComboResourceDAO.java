package io.xlogistx.payment.paypal.daos;

import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.util.GetNVConfig;
import org.zoxweb.shared.util.NVConfig;
import org.zoxweb.shared.util.NVConfigEntity;
import org.zoxweb.shared.util.NVConfigEntityLocal;
import org.zoxweb.shared.util.NVConfigManager;
import org.zoxweb.shared.util.SharedUtil;
import org.zoxweb.shared.util.NVConfigEntity.ArrayType;

@SuppressWarnings("serial")
public class PPComboResourceDAO extends SetNameDescriptionDAO
{
	
	public enum Params
		implements GetNVConfig
	{
		SALE(NVConfigManager.createNVConfigEntity("sale", "Financial transactions related to a payment.", "RelatedResources", false, true, PPSaleDAO.NVC_PAYPAL_SALE_DAO, ArrayType.NOT_ARRAY)),
		
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

	public static final NVConfigEntity NVC_COMBO_RESOURCE_DAO = new NVConfigEntityLocal(
																							"pp_combo_resource_dao",
																							null, 
																							"PPComboResourceDAO", 
																							true, 
																							false, 
																							false, 
																							false, 
																							PPComboResourceDAO.class, 
																							SharedUtil.extractNVConfigs(Params.values()), 
																							null, 
																							false, 
																							SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO
																						);

	public PPComboResourceDAO()
	{
		super(NVC_COMBO_RESOURCE_DAO);
	}
	
	public PPSaleDAO getSale()
	{
		return lookupValue(Params.SALE);
	}
	
	public void setSale(PPSaleDAO sale)
	{
		setValue(Params.SALE, sale);
	}
	
}