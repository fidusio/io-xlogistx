package io.xlogistx.shared.data;

import org.zoxweb.shared.data.AppIDResource;
import org.zoxweb.shared.data.ImageDAO;
import org.zoxweb.shared.util.*;

import java.util.List;

@SuppressWarnings("serial")
public class ItemDAO
    extends AppIDResource
{

  public enum Param
      implements GetNVConfig {

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
      AppIDResource.NVC_APP_ID_RESOURCE
  );


  public ItemDAO() {
    super(NVC_ITEM_DAO);
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