package io.xlogistx.core.client;


import io.xlogistx.shared.data.ItemDAO;
import io.xlogistx.shared.data.PriceDAO;
import io.xlogistx.shared.data.PriceRangeDAO;
import io.xlogistx.shared.data.XXDataConst.AppKey;
import io.xlogistx.shared.util.XXURI;
import org.zoxweb.server.http.HTTPCall;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.net.ssl.SSLCheckDisabler;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.security.JWTProvider;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.server.util.GSONWrapper;
import org.zoxweb.shared.accounting.AmountDAO;
import org.zoxweb.shared.accounting.Currency;
import org.zoxweb.shared.api.APIException;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.crypto.EncryptedDAO;
import org.zoxweb.shared.data.*;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.security.JWT;
import org.zoxweb.shared.util.*;
import org.zoxweb.shared.util.Const.Bool;
import org.zoxweb.shared.util.Const.TimeInMillis;
import org.zoxweb.shared.util.SharedBase64.Base64Type;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;



public class XXClientAPI {

  private static Logger log = Logger.getLogger(XXClientAPI.class.getName());

  public static GSONWrapper GWRAPPER = new GSONWrapper(Base64Type.URL);

  static class StressTest
      implements Runnable {

    private AtomicInteger counter = new AtomicInteger();
    private AtomicInteger fails = new AtomicInteger();
    private AtomicInteger successes = new AtomicInteger();
    private volatile int repeat;
    private volatile AppDeviceDAO add;
    private volatile HTTPMessageConfigInterface hmci;
    private volatile long ts;
    protected volatile UniqueTimeStamp uts = new UniqueTimeStamp();

    //private volatile AtomicInteger seq = new AtomicInteger();
    public StressTest(AppDeviceDAO add, HTTPMessageConfigInterface hmci, int repeat) {
      this.add = add;
      this.hmci = hmci;
      this.repeat = repeat;
      ts = System.currentTimeMillis();
      System.out.println("Stress test started for :" + repeat + " for:" + add);

    }

    @Override
    public void run() {
      int counterValue = counter.incrementAndGet();
      //System.out.println(counterValue);
      //if (counterValue < repeat)
      {
        HTTPMessageConfigInterface hmciToUse = HTTPMessageConfig
            .createAndInit(hmci.getURL(), hmci.getURI(), hmci.getMethod(),
                hmci.isSecureCheckEnabled());
        for (GetNameValue<?> gnv : hmci.getHeaders().values()) {
          hmciToUse.getHeaders().add(gnv);
        }

        for (GetNameValue<?> gnv : hmci.getParameters().values()) {
          hmciToUse.getParameters().add(gnv);
        }
        JWT jwt = JWT
            .createJWT(CryptoConst.JWTAlgo.HS256, add.getSubjectID(), add.getDomainID(),
                add.getAppID());

        hmciToUse.setAuthorization(
            new HTTPAuthorizationJWTBearer(JWTProvider.SINGLETON, add.getAPIKeyAsBytes(), jwt));
        HTTPCall hc = new HTTPCall(hmciToUse);
        try {
          hc.sendRequest();
          successes.incrementAndGet();
        } catch (Exception e) {
          //e.printStackTrace();
//					System.out.println(e);
//                    System.out.println("error:" + fails.incrementAndGet());
        }
      }
      if (counterValue == repeat) {
        //cleanup
        try {
          System.out.println("Deleting device");
          deleteAppDevice(hmci.getURL(), add);
        } catch (Exception e) {
          e.printStackTrace();
        }
        // exit
        ts = System.currentTimeMillis() - ts;
        float rate = ((float) successes.get() / (float) ts) * 1000;
        System.out.println(
            "Stats success:" + successes.get() + " fails:" + fails.get() + " total:" + repeat
                + " duration: " + TimeInMillis.toString(ts) + " rate: " + rate + " /s");
        System.exit(0);

      }
    }
  }


  public static AppIDDAO createItemDAO(String url, String subjectID, String password, String domainID,
                                       String appID) throws IOException {

    String uri = XXURI.APP + "/" + domainID + "/" + appID;
    HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, uri, HTTPMethod.POST);
    hmci.setBasicAuthorization(subjectID, password);
    //hmci.setContent(GSONUtil.toJSON(appDeviceDAO, false));
    hmci.setContentType(HTTPMediaType.APPLICATION_JSON);
    HTTPCall hc = new HTTPCall(hmci, SSLCheckDisabler.SINGLETON);
    return GWRAPPER.fromJSON(hc.sendRequest().getData());
  }

  public static ItemDAO createItemDAO(String appGID, String baseURL) {
    Range<Integer> rangeDAO1 = new Range<Integer>(1, 2);
    AmountDAO moneyValueDAO1 = new AmountDAO(new BigDecimal("25.00"), Currency.USD);
    PriceDAO priceDAO1 = new PriceDAO(rangeDAO1, moneyValueDAO1);

    Range<Integer> rangeDAO2 = new Range<Integer>(3, 5);
    AmountDAO moneyValueDAO2 = new AmountDAO(new BigDecimal("22.50"), Currency.USD);
    PriceDAO priceDAO2 = new PriceDAO(rangeDAO2, moneyValueDAO2);

    Range<Integer> rangeDAO3 = new Range<Integer>(6, 7);
    AmountDAO moneyValueDAO3 = new AmountDAO(new BigDecimal("20.00"), Currency.USD);
    PriceDAO priceDAO3 = new PriceDAO(rangeDAO3, moneyValueDAO3);

    Range<Integer> rangeDAO4 = new Range<Integer>(8, 14);
    AmountDAO moneyValueDAO4 = new AmountDAO(new BigDecimal("16.00"), Currency.USD);
    PriceDAO priceDAO4 = new PriceDAO(rangeDAO4, moneyValueDAO4);

    Range<Integer> rangeDAO5 = new Range<Integer>(15, 20);
    AmountDAO moneyValueDAO5 = new AmountDAO(new BigDecimal("15.00"), Currency.USD);
    PriceDAO priceDAO5 = new PriceDAO(rangeDAO5, moneyValueDAO5);

    Range<Integer> rangeDAO6 = new Range<Integer>(21, 24);
    AmountDAO moneyValueDAO6 = new AmountDAO(new BigDecimal("14.00"), Currency.USD);
    PriceDAO priceDAO6 = new PriceDAO(rangeDAO6, moneyValueDAO6);

    Range<Integer> rangeDAO7 = new Range<Integer>(25, 500);
    AmountDAO moneyValueDAO7 = new AmountDAO(new BigDecimal("13.00"), Currency.USD);
    PriceDAO priceDAO7 = new PriceDAO(rangeDAO7, moneyValueDAO7);

    PriceRangeDAO priceRangeDAO = new PriceRangeDAO();
    priceRangeDAO.getPriceList().add(priceDAO1);
    priceRangeDAO.getPriceList().add(priceDAO2);
    priceRangeDAO.getPriceList().add(priceDAO3);
    priceRangeDAO.getPriceList().add(priceDAO4);
    priceRangeDAO.getPriceList().add(priceDAO5);
    priceRangeDAO.getPriceList().add(priceDAO6);
    priceRangeDAO.getPriceList().add(priceDAO7);

    ImageDAO imageDAO = new ImageDAO();
    imageDAO.setFormat(ImageDAO.ImageFormat.IMAGE_PNG);
    imageDAO.setName("item-tank.png");
    imageDAO.setResourceLocator(baseURL + "/images/pxp/item-tank.png");
    //imageDAO.setResourceLocator(baseURL + "" + XXURI.IMAGE + "/" + appIDDAO.getDomainID() + "/" + appIDDAO.getAppID() + "/item-tank.png");

    ItemDAO itemDAO = new ItemDAO();
    //itemDAO.setAppGUID(appGID);
    itemDAO.setDescription("20 LB Propane Tank - Exchange");
    itemDAO.setPriceRange(priceRangeDAO);
    itemDAO.getImages().add(imageDAO);



    return itemDAO;
  }


  public static DeviceDAO createDeviceDAO() {
    DeviceDAO deviceDAO = new DeviceDAO();
    deviceDAO.setDeviceID(UUID.randomUUID().toString());
    deviceDAO.setManufacturer("android");
    deviceDAO.setModel("7");
    deviceDAO.setVersion("10");
    return deviceDAO;
  }

  public static AppDeviceDAO createAppDeviceDAO(String domainID, String appID) {
    AppDeviceDAO ret = new AppDeviceDAO();
    ret.setDevice(createDeviceDAO());
    ret.setDomainID(domainID);
    ret.setAppID(appID);
    return ret;
  }

  public static AppConfigDAO lookupAppConfigDAO(String url, String subjectID, String password,
      String domainID, String appID) throws APIException, IOException {
    String uri = "" + XXURI.APP_CONFIG + "/" + domainID + "/" + appID;
    System.out.println(uri);
    HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, uri, HTTPMethod.GET);
    hmci.setBasicAuthorization(subjectID, password);
    hmci.setContentType(HTTPMediaType.APPLICATION_JSON);
    HTTPCall hc = new HTTPCall(hmci, SSLCheckDisabler.SINGLETON);
    return GWRAPPER.fromJSON(hc.sendRequest().getData());
  }

  public static AppConfigDAO updateAppConfigDAO(String urlIn, String subjectID, String password,
      String domainID, String appID, File jsonFile) throws APIException, IOException {
    AppConfigDAO ret = lookupAppConfigDAO(urlIn, subjectID, password, domainID, appID);

//		String url = "https://www.zipcodeapi.com";
//        String uri = "rest";
//        String apiKey = "yuvBMa4vBHGCQ6Hoy0RGT3ZrVwQ2t9N1DjDqtHW5oDHfJoDhpuYiyXKutAwXKkZo";
//        String format = "json";
//        String distance = "50";
//        String zipCode = "90025";
//        String units = "mile";
//
//        HTTPMessageConfig hmc = (HTTPMessageConfig) HTTPMessageConfig.createAndInit(url, uri, HTTPMethod.GET);
//        hmc.setName(XXConsts.ZIP_CODE_API_CONFIG);
//        hmc.setHTTPParameterFormatter(HTTPParameterFormatter.URI_REST_ENCODED);
//        hmc.getParameters().add(new NVPair(XXConsts.PARAM_API_KEY, apiKey));
//        hmc.getParameters().add(new NVPair(XXConsts.PARAM_FORMAT, XXConsts.PARAM_RADIUS + format));
//        hmc.getParameters().add(new NVPair(XXConsts.PARAM_ZIP_CODE, zipCode));
//        hmc.getParameters().add(new NVPair(XXConsts.PARAM_DISTANCE, distance));
//        hmc.getParameters().add(new NVPair(XXConsts.PARAM_UNITS, units));
//        
//        
//        System.out.println(GSONUtil.toJSON(hmc, true, false, true));
//    HTTPMessageConfig httpMessageConfig =  GWRAPPER
//            .fromJSON(IOUtil.inputStreamToString(jsonFile), HTTPMessageConfig.class, Base64Type.DEFAULT);

    NVEntity nve = GSONUtil.fromJSON(IOUtil.inputStreamToString(jsonFile));
//    nvg.setName("zip_code_api_config");
    log.info(""+nve.getClass());
    //ret.getProperties().add(nve);

    //ret.getProperties().add(nvg);
    log.info("Ret:" + ret);

    String commandURI = "" + XXURI.APP_CONFIG + "/" + domainID + "/" + appID;
    HTTPMessageConfigInterface hmci = HTTPMessageConfig
        .createAndInit(urlIn, commandURI, HTTPMethod.PATCH);
    hmci.setBasicAuthorization(subjectID, password);
    hmci.setContentType(HTTPMediaType.APPLICATION_JSON);
    hmci.setContent(GWRAPPER.toJSON(nve, false));

    HTTPCall hc = new HTTPCall(hmci, SSLCheckDisabler.SINGLETON);
    return GWRAPPER.fromJSON(hc.sendRequest().getData());


  }

  public static AppIDDAO createAppID(String url, String subjectID, String password, String domainID,
      String appID) throws IOException {

    String uri = XXURI.APP + "/" + domainID + "/" + appID;
    HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, uri, HTTPMethod.POST);
    hmci.setBasicAuthorization(subjectID, password);
    //hmci.setContent(GSONUtil.toJSON(appDeviceDAO, false));
    hmci.setContentType(HTTPMediaType.APPLICATION_JSON);
    HTTPCall hc = new HTTPCall(hmci, SSLCheckDisabler.SINGLETON);
    return GWRAPPER.fromJSON(hc.sendRequest().getData());
  }

  public static AppIDDAO deleteAppID(String url, String subjectID, String password, String domainID,
      String appID) throws IOException {
    AppDeviceDAO appDeviceDAO = new AppDeviceDAO();

    appDeviceDAO.setDomainID(domainID);//setAppGUID(new AppIDDAO(domainID, appID).getAppGUID());
    appDeviceDAO.setAppID(appID);
    String uri = "" + XXURI.APP + "/" + domainID + "/" + appID;
    HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, uri, HTTPMethod.DELETE);
    hmci.setBasicAuthorization(subjectID, password);
    //hmci.setContent(GSONUtil.toJSON(appDeviceDAO, false));
    hmci.setContentType(HTTPMediaType.APPLICATION_JSON);
    HTTPCall hc = new HTTPCall(hmci, SSLCheckDisabler.SINGLETON);
    return GWRAPPER.fromJSON(hc.sendRequest().getData());
  }


  public static AppDeviceDAO createAppDevice(String url, String subjectID, String password,
      String domainID, String appID)
      throws IOException, InstantiationException, IllegalAccessException, ClassNotFoundException {
    AppDeviceDAO appDeviceDAO = createAppDeviceDAO(domainID, appID);

    String uri = XXURI.LOGIN + "/" + domainID + "/" + appID;
    HTTPMessageConfigInterface hmci = createHMCI(url, uri, HTTPMethod.POST, subjectID, password);

    hmci.setContent(GWRAPPER.toJSON(appDeviceDAO, false));
    HTTPCall hc = new HTTPCall(hmci);
    HTTPResponseData hrd = hc.sendRequest();
    return GWRAPPER.fromJSON(hrd.getData());
  }

  public static void login(String url, String subjectID, String password, String domainID,
      String appID) throws IOException {
    String uri = XXURI.LOGIN + "/" + domainID + "/" + appID;
    System.out.println(uri);
    HTTPMessageConfigInterface hmci = createHMCI(url, uri, HTTPMethod.GET, subjectID, password);
    HTTPCall hc = new HTTPCall(hmci);
    HTTPResponseData hrd = hc.sendRequest();

    System.out.println(hrd);
  }


  public static void deleteAppDevice(String url, AppDeviceDAO apd) throws IOException {
    JWT jwt = JWT
        .createJWT(CryptoConst.JWTAlgo.HS256, apd.getSubjectID(), apd.getDomainID(),
            apd.getAppID());
    String uri = XXURI.DEREGISTRATION;
    HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, uri, HTTPMethod.DELETE);

    hmci.setAuthorization(
        new HTTPAuthorizationJWTBearer(JWTProvider.SINGLETON, apd.getAPIKeyAsBytes(), jwt));
    HTTPCall hc = new HTTPCall(hmci);
    HTTPResponseData rd = hc.sendRequest();
    System.out.println(rd);

  }


  public static void delayTest(String url, String subjectID, String password, String domainID,
      String appID, long delay)
      throws IOException, IllegalAccessException, ClassNotFoundException, InstantiationException {

    AppDeviceDAO apd = createAppDevice(url, subjectID, password, domainID, appID);

    JWT jwt = JWT.createJWT(CryptoConst.JWTAlgo.HS256, apd.getSubjectID(), domainID, appID);
    jwt.getPayload().setIssuedAt(Const.TimeInMillis.SECOND.convertTo(System.currentTimeMillis() - delay));
    String uri = XXURI.LOGIN;
    HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, uri, HTTPMethod.GET);

    hmci.setAuthorization(
        new HTTPAuthorizationJWTBearer(JWTProvider.SINGLETON, apd.getAPIKeyAsBytes(), jwt));
    HTTPCall hc = new HTTPCall(hmci);
    try {
      HTTPResponseData rd = hc.sendRequest();
      System.out.println(rd);
    } catch (Exception e) {
      e.printStackTrace();
    }

    try {
      HTTPResponseData rd = hc.sendRequest();
      System.out.println(rd);
    } catch (Exception e) {
      System.out.println("failed on repeat" + e);
    }

    deleteAppDevice(url, apd);

  }


  public static void stressTest(String url, String subjectID, String password, String domainID,
      String appID, int repeat, long delay)
      throws IOException, IllegalAccessException, ClassNotFoundException, InstantiationException {

    AppDeviceDAO add = createAppDevice(url, subjectID, password, domainID, appID);

    String uri = XXURI.LOGIN;
    HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, uri, HTTPMethod.GET);
    StressTest st = new StressTest(add, hmci, repeat);

    for (int i = 0; i < repeat; i++) {
      //TaskUtil.defaultTaskScheduler().queue(new AppointmentDefault((i/1000)*delay), st);
      TaskUtil.defaultTaskProcessor().execute(st);
    }

  }


  public static void encryptionTest(String url, String subjectID, String password, String domainID,
      String appID, int repeat, boolean autoDelete)
      throws IOException, IllegalAccessException, ClassNotFoundException, InstantiationException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, SignatureException {

    AppDeviceDAO add = null;
    try {
      add = createAppDevice(url, subjectID, password, domainID, appID);
      for (int i = 0; i < repeat; i++) {
        String sData = "hello";
        EncryptedDAO ed = new EncryptedDAO();
        ed = CryptoUtil.encryptDAO(ed, add.getAPIKeyAsBytes(), SharedStringUtil.getBytes(sData));
        String json = GWRAPPER.toJSON(ed, false, false, false);
        System.out.println(json);
        ed = GWRAPPER.fromJSON(json, EncryptedDAO.class);
        byte data[] = CryptoUtil.decryptEncryptedDAO(ed, add.getAPIKeyAsBytes());
        System.out.println("Decrypted data:" + SharedStringUtil.toString(data));
      }
    } finally {
      if (autoDelete && add != null) {
        deleteAppDevice(url, add);
      }
    }

  }


  public static void renewToken(String url, String subjectID, String password, String domainID,
      String appID, boolean encrypt, boolean autoDelete)
      throws IOException, IllegalAccessException, ClassNotFoundException, InstantiationException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, SignatureException {

    AppDeviceDAO add = null;
    try {
      add = createAppDevice(url, subjectID, password, domainID, appID);
      System.out.println(GWRAPPER.toJSON(add, false, false, true));
      String uri = encrypt ? SharedUtil
          .toCanonicalID('/', XXURI.API_KEY_BASE, XXURI.C_RENEW, XXURI.C_ENCRYPT)
          : SharedUtil.toCanonicalID('/', XXURI.API_KEY_BASE, XXURI.C_RENEW);

      JWT jwt = JWT
          .createJWT(CryptoConst.JWTAlgo.HS256, add.getSubjectID(), add.getDomainID(),
              add.getAppID());

      HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, uri, HTTPMethod.PATCH);

      hmci.setAuthorization(
          new HTTPAuthorizationJWTBearer(JWTProvider.SINGLETON, add.getAPIKeyAsBytes(), jwt));
      HTTPCall hc = new HTTPCall(hmci);
      HTTPResponseData hrd = hc.sendRequest();

      NVEntity nve = GWRAPPER.fromJSON(hrd.getData());
      if (encrypt && nve instanceof EncryptedDAO) {
        add = GWRAPPER
            .fromJSON(CryptoUtil.decryptEncryptedDAO((EncryptedDAO) nve, add.getAPIKeyAsBytes()));
      } else {
        add = (AppDeviceDAO) nve;
      }
      if (nve != add) {
        System.out.println(SharedStringUtil.toString(hrd.getData()));
      }
      System.out.println(GWRAPPER.toJSON(add, false, false, true));

    } finally {
      if (autoDelete && add != null) {
        deleteAppDevice(url, add);
      }
    }

  }

  public static void updateUserRole(String url, String subjectID, String password, String domainID,
      String appID, String subjectToUpdate, String roleName) throws IOException {
    String uri = XXURI.MANAGEMENT_USERS;
    HTTPMessageConfigInterface hmci = createHMCI(url, uri, HTTPMethod.PATCH, subjectID, password);
    NVGenericMap params = new NVGenericMap();

    // subject_id
    // app_gid
    // role = app_admin, app_user, app_user_provider
    // crud= add, delete

    // if super_admin role we can do it for any domain

    // if app_admin can only do it for his domain
    params.add("subject_id", subjectToUpdate);
    params.add("app_gid", AppIDDAO.appIDSubjectID(domainID, appID));
    params.add("role", roleName);
    hmci.setContent(GWRAPPER.toJSONGenericMap(params, false, false, false));
    HTTPCall hc = new HTTPCall(hmci);
    hc.sendRequest();
  }


  public static void deleteUserRole(String url, String subjectID, String password, String domainID,
      String appID, String subjectToUpdate, String roleName) throws IOException {
    String uri = XXURI.MANAGEMENT_USERS;
    HTTPMessageConfigInterface hmci = createHMCI(url, uri, HTTPMethod.DELETE, subjectID, password);
    NVGenericMap params = new NVGenericMap();

    // subject_id
    // app_gid
    // role = app_admin, app_user, app_user_provider
    // crud= add, delete

    // if super_admin role we can do it for any domain

    // if app_admin can only do it for his domain
    params.add("subject_id", subjectToUpdate);
    params.add("app_gid", AppIDDAO.appIDSubjectID(domainID, appID));
    params.add("role", roleName);
    hmci.setContent(GWRAPPER.toJSONGenericMap(params, false, false, false));
    HTTPCall hc = new HTTPCall(hmci);
    hc.sendRequest();
  }

  public static void deleteUser(String url, String subjectID, String password, String userToDelete)
          throws IOException {
    String uri = XXURI.USER_DELETE;
    HTTPMessageConfigInterface hmci = createHMCI(url, uri, HTTPMethod.DELETE, subjectID, password);
    NVGenericMap params = new NVGenericMap();
    params.add(MetaToken.SUBJECT_ID,userToDelete);

    // subject_id
    // app_gid
    // role = app_admin, app_user, app_user_provider
    // crud= add, delete

    // if super_admin role we can do it for any domain

    // if app_admin can only do it for his domain
    hmci.setContent(GWRAPPER.toJSONGenericMap(params, false, false, false));
    HTTPCall hc = new HTTPCall(hmci);
    hc.sendRequest();
  }

  public static void simpleRegistration(String url, String subjectID, String password)
      throws IOException {
    String uri = XXURI.REGISTRATION;
    HTTPMessageConfigInterface hmci = createHMCI(url, uri, HTTPMethod.POST, subjectID, password);
    HTTPCall hc = new HTTPCall(hmci);
    HTTPResponseData hrd = hc.sendRequest();
    System.out.println(hrd);
  }


  static HTTPMessageConfigInterface createHMCI(String url, String uri, HTTPMethod method,
      String subjectID, String password) {
    HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, uri, method);
    hmci.setBasicAuthorization(subjectID, password);
    hmci.setContentType(HTTPMediaType.APPLICATION_JSON);
    hmci.setSecureCheckEnabled(false);
    return hmci;
  }


  public static void changePassword(String url, String subjectID, String password,
      String newPassword) throws IOException {
    String uri = "" + XXURI.PASSWORD_CHANGE;
    HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, uri, HTTPMethod.POST);
    hmci.setBasicAuthorization(subjectID, password);;
    hmci.getParameters().add(new NVPair(AppKey.CURRENT_PASSWORD, password));
    hmci.getParameters().add(new NVPair(AppKey.NEW_PASSWORD, newPassword));

    hmci.setContentType(HTTPMediaType.APPLICATION_WWW_URL_ENC);
    HTTPCall hc = new HTTPCall(hmci, SSLCheckDisabler.SINGLETON);
    hc.sendRequest();
  }


  public static void main(String... args) {

    try {
      TaskUtil.setThreadMultiplier(4);
      int index = 0;
      String command = args[index++].toLowerCase();
      String url = args[index++];
      String subjectID = args[index++];
      String password = args[index++];
      String domainID = args[index++];
      String appID = args[index++];
      AppIDDAO appIDDAO = null;
      AppConfigDAO appConfigDAO;
      File file;
      switch (command) {
        case "createapp":
          appIDDAO = createAppID(url, subjectID, password, domainID, appID);
          System.out.println(appIDDAO + " created");
          break;
        case "createappdevice":
          AppDeviceDAO device = createAppDevice(url, subjectID, password, domainID, appID);
          System.out.println(device + " created");
          break;
        case "deleteapp":
          appIDDAO = deleteAppID(url, subjectID, password, domainID, appID);
          System.out.println(appIDDAO + " deleted");
          break;
        case "getappconfig":
          appConfigDAO = lookupAppConfigDAO(url, subjectID, password, domainID, appID);
          System.out.println(GWRAPPER.toJSON(appConfigDAO, true, Base64Type.DEFAULT));
          break;
        case "updateappconfig":
          file = new File(args[index++]);
          appConfigDAO = updateAppConfigDAO(url, subjectID, password, domainID, appID, file);
          System.out.println(GWRAPPER.toJSON(appConfigDAO, true, Base64Type.DEFAULT));
          break;

        case "changepassword":
          changePassword(url, subjectID, password, args[index++]);
          System.out.println("Password changed successfully");
          break;
        case "updateuserrole":
          updateUserRole(url, subjectID, password, domainID, appID, args[index++], args[index++]);
          System.out.println("user role updated");
          break;
        case "deleteuserrole":
          deleteUserRole(url, subjectID, password, domainID, appID, args[index++], args[index++]);
          System.out.println("user role updated");
          break;
        case "simpleregistration":
          simpleRegistration(url, subjectID, password);
          break;

        case "login":
          login(url, subjectID, password, domainID, appID);
          break;
        case "deleteuser":
          String userIDToDelete = args[index++];
          deleteUser(url, subjectID, password, userIDToDelete);
          break;
        case "delaytest":
          //for(int i=0; i < 1000; i++)
          delayTest(url, subjectID, password, domainID, appID,
              args.length > index ? TimeInMillis.toMillis(args[index++]) : 0);
          break;
        case "encryptiontest":
          encryptionTest(url, subjectID, password, domainID, appID,
              args.length > index ? Integer.parseInt(args[index++]) : 1,
              args.length > index ? Bool.lookupValue(args[index++]) : true);
          break;
        case "stresstest":
          //for(int i=0; i < 1000; i++)
          stressTest(url, subjectID, password, domainID, appID, Integer.parseInt(args[index++]),
              args.length > index ? TimeInMillis.toMillis(args[index++]) : 0);
          break;
        case "renewtoken":
          //for(int i=0; i < 1000; i++)
          renewToken(url, subjectID, password, domainID, appID,
              args.length > index ? Bool.lookupValue(args[index++]) : false,
              args.length > index ? Bool.lookupValue(args[index++]) : false);
          break;
        case "createitem":
          //AppIDDAO.toAppID(domainID, appID).getAppGUID();
          ItemDAO item = createItemDAO(AppIDDAO.toAppID(domainID, appID).toCanonicalID(), "http://localhost");

          renewToken(url, subjectID, password, domainID, appID,
                  args.length > index ? Bool.lookupValue(args[index++]) : false,
                  args.length > index ? Bool.lookupValue(args[index++]) : false);
          break;
        default:


          System.err.println(command + " not found.");
      }


    } catch (Exception e) {
      e.printStackTrace();
      System.out.println("Command url subject_id password domainid appid");
    }
  }
}
