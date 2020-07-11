package io.xlogistx.shared.data;


import org.zoxweb.shared.data.NVEntityFactory;
import org.zoxweb.shared.data.ZWDataFactory;
import org.zoxweb.shared.util.*;

/**
 * The NVEntity factory creates NVEntity objects.
 */
public class XXDataFactory
    implements NVEntityFactory {

  public enum XXNVEntityTypeClass
      implements GetName, NVEntityInstance {


    ITEM_DAO(ItemDAO.class.getName()) {
      @SuppressWarnings("unchecked")
      @Override
      public ItemDAO newInstance() {
        return new ItemDAO();
      }

      @Override
      public NVConfigEntity getNVConfigEntity() {
        return ItemDAO.NVC_ITEM_DAO;
      }
    },
    ORDER_DAO(OrderDAO.class.getName()) {
      @SuppressWarnings("unchecked")
      @Override
      public OrderDAO newInstance() {
        return new OrderDAO();
      }

      @Override
      public NVConfigEntity getNVConfigEntity() {
        return OrderDAO.NVC_ORDER_DAO;
      }
    },
    ORDER_ITEM_DAO(OrderItemDAO.class.getName()) {
      @SuppressWarnings("unchecked")
      @Override
      public OrderItemDAO newInstance() {
        return new OrderItemDAO();
      }

      @Override
      public NVConfigEntity getNVConfigEntity() {
        return OrderItemDAO.NVC_ORDER_ITEM_DAO;
      }
    },
    ORDER_TRANSACTION_DAO(OrderTransactionDAO.class.getName()) {
      @SuppressWarnings("unchecked")
      @Override
      public OrderTransactionDAO newInstance() {
        return new OrderTransactionDAO();
      }

      @Override
      public NVConfigEntity getNVConfigEntity() {
        return OrderTransactionDAO.NVC_ORDER_TRANSACTION_DAO;
      }
    },
    PRICE_DAO(PriceDAO.class.getName()) {
      @SuppressWarnings("unchecked")
      @Override
      public PriceDAO newInstance() {
        return new PriceDAO();
      }

      @Override
      public NVConfigEntity getNVConfigEntity() {
        return PriceDAO.NVC_PRICE_DAO;
      }
    },
    PRICE_RANGE_DAO(PriceRangeDAO.class.getName()) {
      @SuppressWarnings("unchecked")
      @Override
      public PriceRangeDAO newInstance() {
        return new PriceRangeDAO();
      }

      @Override
      public NVConfigEntity getNVConfigEntity() {
        return PriceRangeDAO.NVC_PRICE_RANGE_DAO;
      }
    },
    ZIP_CODE_DISTANCE_DAO(ZipCodeDistanceDAO.class.getName()) {
      @SuppressWarnings("unchecked")
      @Override
      public ZipCodeDistanceDAO newInstance() {
        return new ZipCodeDistanceDAO();
      }

      @Override
      public NVConfigEntity getNVConfigEntity() {
        return ZipCodeDistanceDAO.NVC_ZIP_CODE_DISTANCE_DAO;
      }
    },
    ZIP_CODE_DISTANCE_LIST_DAO(ZipCodeDistanceListDAO.class.getName()) {
      @SuppressWarnings("unchecked")
      @Override
      public ZipCodeDistanceListDAO newInstance() {
        return new ZipCodeDistanceListDAO();
      }

      @Override
      public NVConfigEntity getNVConfigEntity() {
        return ZipCodeDistanceListDAO.NVC_ZIP_CODE_DISTANCE_LIST_DAO;
      }
    },

    ;

    private String name;

    XXNVEntityTypeClass(String name) {
      this.name = name;
    }

    @Override
    public String getName() {
      return name;
    }
  }

  /**
   * Declares that only one instance of this class can be created.
   */
  public static final XXDataFactory SINGLETON = new XXDataFactory();

  /**
   * The default constructor is declared private to prevent outside instantiation.
   */
  private XXDataFactory() {
    //ZWDataFactory.SINGLETON.registerFactory(this);
  }

  /**
   * Creates NVEntity based on given canonical ID.
   */
  public <V extends NVEntity> V createNVEntity(String canonicalID) {
    V ret = ZWDataFactory.SINGLETON.createNVEntity(canonicalID);

    if (ret == null && !SharedStringUtil.isEmpty(canonicalID)) {
      XXNVEntityTypeClass type = (XXNVEntityTypeClass) SharedUtil
          .lookupEnum(canonicalID, XXNVEntityTypeClass.values());

      if (type == null) {
        for (XXNVEntityTypeClass nveTypeClass : XXNVEntityTypeClass.values()) {
          if (canonicalID.equals(nveTypeClass.getNVConfigEntity().toCanonicalID()) || canonicalID
              .equals(nveTypeClass.getNVConfigEntity().getName())) {
            type = nveTypeClass;
            break;
          }
        }
      }

      if (type != null) {
        return type.newInstance();
      }
    }

    return ret;
  }

}