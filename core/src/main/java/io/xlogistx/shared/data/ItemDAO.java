package io.xlogistx.shared.data;

import org.zoxweb.shared.data.ImageDAO;
import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.util.*;

import java.util.List;

@SuppressWarnings("serial")
public class ItemDAO
    extends SetNameDescriptionDAO
    implements AppGlobalID<String> {

  public enum Param
      implements GetNVConfig {

    APP_GUID(NVConfigManager
        .createNVConfig("app_guid", "App Global ID", "AppGUID", true, true, String.class)),
    PRICE_RANGE(NVConfigManager
        .createNVConfigEntity("price_range", "Price range", "Price Range", true, true,
            PriceRangeDAO.class, NVConfigEntity.ArrayType.NOT_ARRAY)),
    AVAILABLE_QUANTITY(NVConfigManager
        .createNVConfig("available_quantity", "Available quantity", "Available Quantity", true,
            true, int.class)),
    IMAGES(NVConfigManager
        .createNVConfigEntity("images", "Item images", "Images", false, true, true, false,
            ImageDAO.NVC_IMAGE_DAO, NVConfigEntity.ArrayType.LIST)),

    ;

    private final NVConfig nvc;

    Param(NVConfig nvc) {
      this.nvc = nvc;
    }

    @Override
    public NVConfig getNVConfig() {
      return nvc;
    }
  }

  public static final NVConfigEntity NVC_ITEM_DAO = new NVConfigEntityLocal(
      "item_dao",
      null,
      ItemDAO.class.getSimpleName(),
      true,
      false,
      false,
      false,
      ItemDAO.class,
      SharedUtil.extractNVConfigs(Param.values()),
      null,
      false,
      SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO
  );


  public ItemDAO() {
    super(NVC_ITEM_DAO);
  }

  /**
   * Returns the App Global ID.
   */
  @Override
  public String getAppGUID() {
    return lookupValue(Param.APP_GUID);
  }

  /**
   * Sets the App Global ID.
   */
  @Override
  public void setAppGUID(String appGID) {
    setValue(Param.APP_GUID, appGID);
  }

  /**
   * Returns the price range.
   */
  public PriceRangeDAO getPriceRange() {
    return lookupValue(Param.PRICE_RANGE);
  }

  /**
   * Sets the price range.
   */
  public void setPriceRange(PriceRangeDAO priceRange) {
    setValue(Param.PRICE_RANGE, priceRange);
  }

  /**
   * Returns the available quantity.
   */
  public int getAvailableQuantity() {
    return lookupValue(Param.AVAILABLE_QUANTITY);
  }

  /**
   * Sets the available quantity.
   */
  public void setAvailableQuantity(int availableQuantity) {
    setValue(Param.AVAILABLE_QUANTITY, availableQuantity);
  }

  /**
   * Returns list of item images.
   */
  public List<ImageDAO> getImages() {
    return lookupValue(Param.IMAGES);
  }

  /**
   * Sets list of item images.
   */
  public void setImages(List<ImageDAO> images) {
    setValue(Param.IMAGES, images);
  }

}