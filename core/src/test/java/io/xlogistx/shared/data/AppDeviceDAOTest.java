package io.xlogistx.shared.data;


import org.junit.jupiter.api.Test;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.data.AppDeviceDAO;
import org.zoxweb.shared.data.AppIDDAO;
import org.zoxweb.shared.data.DeviceDAO;
import org.zoxweb.shared.util.Const.Status;

import java.security.NoSuchAlgorithmException;
import java.util.UUID;

/**
 * Created on 7/15/17
 */
public class AppDeviceDAOTest {

  @Test
  public void testAppDeviceDAO() throws NoSuchAlgorithmException {

    DeviceDAO deviceDAO = new DeviceDAO();
    deviceDAO.setDeviceID(UUID.randomUUID().toString());
    deviceDAO.setManufacturer("Apple");
    deviceDAO.setModel("iPhone 7");
    deviceDAO.setPlatform("iOS");
    deviceDAO.setVersion("10.3.2");
    deviceDAO.setVirtual(false);
    deviceDAO.setSerialNumber(UUID.randomUUID().toString());

    AppDeviceDAO appDeviceDAO = new AppDeviceDAO();
    appDeviceDAO.setAppGID(new AppIDDAO("xlogistx.io", "io/xlogistx").getAppGID());
    appDeviceDAO.setUserID(UUID.randomUUID().toString());
    appDeviceDAO.setSubjectID(UUID.randomUUID().toString());

    appDeviceDAO.setAPIKey(CryptoUtil.generateKey(CryptoConst.CryptoAlgo.AES, 256).getEncoded());

    appDeviceDAO.setStatus(Status.ACTIVE);
    appDeviceDAO.setDevice(deviceDAO);

    System.out.println(appDeviceDAO);
  }


}
