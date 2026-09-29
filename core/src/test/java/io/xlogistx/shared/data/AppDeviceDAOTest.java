package io.xlogistx.shared.data;


import org.junit.jupiter.api.Test;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.shared.app.AppIDDefault;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.data.AppDeviceInfo;
import org.zoxweb.shared.data.DeviceInfo;
import org.zoxweb.shared.util.Const.Status;

import java.security.NoSuchAlgorithmException;
import java.util.UUID;

/**
 * Created on 7/15/17
 */
public class AppDeviceDAOTest {

  @Test
  public void testAppDeviceDAO() throws NoSuchAlgorithmException {

    DeviceInfo deviceDAO = new DeviceInfo();
    deviceDAO.setDeviceID(UUID.randomUUID().toString());
    deviceDAO.setManufacturer("Apple");
    deviceDAO.setModel("iPhone 7");
    deviceDAO.setPlatform("iOS");
    deviceDAO.setVersion("10.3.2");
    deviceDAO.setVirtual(false);
    deviceDAO.setSerialNumber(UUID.randomUUID().toString());

    AppDeviceInfo appDeviceDAO = new AppDeviceInfo();
//    appDeviceDAO.setDomainID("xlogistx.io");
    appDeviceDAO.setAppID(new AppIDDefault("xlogistx.io","io/xlogistx"));
    appDeviceDAO.setSubjectGUID(UUID.randomUUID().toString());
    appDeviceDAO.setSubjectID(UUID.randomUUID().toString());

    appDeviceDAO.setAPIKeyAsBytes(CryptoUtil.generateSecretKey(CryptoConst.CryptoAlgo.AES, 256).getEncoded());

    appDeviceDAO.setStatus(Status.ACTIVE);
    appDeviceDAO.setDevice(deviceDAO);

    System.out.println(appDeviceDAO);
  }


}
