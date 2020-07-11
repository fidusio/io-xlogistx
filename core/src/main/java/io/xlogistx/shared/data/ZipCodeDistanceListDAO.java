package io.xlogistx.shared.data;

import org.zoxweb.shared.data.AddressDAO;
import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.util.*;

import java.util.List;

/**
 * Created on 7/1/17
 */
@SuppressWarnings("serial")
public class ZipCodeDistanceListDAO
    extends SetNameDescriptionDAO {

  public enum Param
      implements GetNVConfig {

    ZIP_CODES(NVConfigManager
        .createNVConfigEntity("zip_codes", "Zip Codes", "ZipCodes", false, true,
            ZipCodeDistanceDAO.NVC_ZIP_CODE_DISTANCE_DAO, NVConfigEntity.ArrayType.GET_NAME_MAP)),

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

  public static final NVConfigEntity NVC_ZIP_CODE_DISTANCE_LIST_DAO = new NVConfigEntityLocal(
      "zip_code_distance_list_dao",
      null,
      ZipCodeDistanceListDAO.class.getSimpleName(),
      true,
      false,
      false,
      false,
      ZipCodeDistanceListDAO.class,
      SharedUtil.extractNVConfigs(Param.values()),
      null,
      false,
      SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO
  );


  public ZipCodeDistanceListDAO() {
    super(NVC_ZIP_CODE_DISTANCE_LIST_DAO);
  }


  public ArrayValues<ZipCodeDistanceDAO> getZipCodes() {
    return (ArrayValues<ZipCodeDistanceDAO>) lookup(Param.ZIP_CODES);
  }

  public void setZipCodes(List<ZipCodeDistanceDAO> zipCodes) {
    ArrayValues<ZipCodeDistanceDAO> zipCodesAV = getZipCodes();
    zipCodesAV.clear();
    for(ZipCodeDistanceDAO z : zipCodes)
    {
      zipCodesAV.add(z);
    }
  }

  public boolean isWithinRange(AddressDAO addressToCheck) {
    if (addressToCheck != null && addressToCheck.getZIPOrPostalCode() != null) {
      return isWithinRange(addressToCheck.getZIPOrPostalCode());
    }

    return false;
  }

  public boolean isWithinRange(String zipCodeToCheck) {
    if (!SharedStringUtil.isEmpty(zipCodeToCheck)) {
      return (getZipCodes().get(zipCodeToCheck) != null);
    }

    return false;
  }

}