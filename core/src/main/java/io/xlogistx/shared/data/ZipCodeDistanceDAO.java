package io.xlogistx.shared.data;

import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.util.*;

/**
 * Created on 7/1/17
 */
@SuppressWarnings("serial")
public class ZipCodeDistanceDAO
    extends SetNameDescriptionDAO {

  public enum Param
      implements GetNVConfig {

    ZIP_CODE(NVConfigManager
        .createNVConfig("zip_code", "Zip Code", "ZipCode", true, true, String.class)),
    DISTANCE(NVConfigManager
        .createNVConfig("distance", "Order ID", "Distance", true, true, double.class)),
    CITY(NVConfigManager.createNVConfig("city", "City", "City", false, true, String.class)),
    STATE(NVConfigManager.createNVConfig("state", "State", "State", false, true, String.class)),

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

  public static final NVConfigEntity NVC_ZIP_CODE_DISTANCE_DAO = new NVConfigEntityPortable(
      "zip_code_distance_dao",
      null,
      ZipCodeDistanceDAO.class.getSimpleName(),
      true,
      false,
      false,
      false,
      ZipCodeDistanceDAO.class,
      SharedUtil.extractNVConfigs(Param.values()),
      null,
      false,
      SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO
  );


  public ZipCodeDistanceDAO() {
    super(NVC_ZIP_CODE_DISTANCE_DAO);
  }

  public String getName() {
    return getZipCode();
  }

  public String getZipCode() {
    return lookupValue(Param.ZIP_CODE);
  }

  public void setZipCode(String zipCode) {
    setValue(Param.ZIP_CODE, zipCode);
  }

  public double getDistance() {
    return lookupValue(Param.DISTANCE);
  }

  public void setDistance(double distance) {
    setValue(Param.DISTANCE, distance);
  }

  public String getCity() {
    return lookupValue(Param.CITY);
  }

  public void setCity(String city) {
    setValue(Param.CITY, city);
  }

  public String getState() {
    return lookupValue(Param.STATE);
  }

  public void setState(String state) {
    setValue(Param.STATE, state);
  }

}