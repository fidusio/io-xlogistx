package io.xlogistx.shared.data;

import org.zoxweb.server.util.GSONUtil;


import java.io.IOException;

/**
 * Created on 7/3/17
 */
public class ZipCodeDistanceListDAOTest {

  public static void main(String[] args)
      throws IOException, IllegalAccessException, ClassNotFoundException, InstantiationException {
    ZipCodeDistanceDAO zipCodeDistance1 = new ZipCodeDistanceDAO();
    zipCodeDistance1.setZipCode("90025");
    zipCodeDistance1.setDistance(20.00);
    zipCodeDistance1.setCity("Los Angeles");
    zipCodeDistance1.setState("CA");

    ZipCodeDistanceDAO zipCodeDistance2 = new ZipCodeDistanceDAO();
    zipCodeDistance2.setZipCode("90015");
    zipCodeDistance2.setDistance(20.00);
    zipCodeDistance2.setCity("Los Angeles");
    zipCodeDistance2.setState("CA");

    ZipCodeDistanceListDAO zipCodeDistanceListDAO = new ZipCodeDistanceListDAO();
    zipCodeDistanceListDAO.getZipCodes().add(zipCodeDistance1);
    zipCodeDistanceListDAO.getZipCodes().add(zipCodeDistance2);

    String toJson = GSONUtil.toJSON(zipCodeDistanceListDAO, true, false, false);
    System.out.println("TO JSON: " + toJson);

    ZipCodeDistanceListDAO fromJson = GSONUtil.fromJSON(toJson, ZipCodeDistanceListDAO.class);
    System.out.println(fromJson);

    System.out.println(GSONUtil.toJSON(fromJson, true, false, false));

    System.out.println(zipCodeDistanceListDAO.isWithinRange("90066"));
    System.out.println(zipCodeDistanceListDAO.isWithinRange("90025"));


  }

}
