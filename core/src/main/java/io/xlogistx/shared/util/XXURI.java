package io.xlogistx.shared.util;

import org.zoxweb.shared.util.SharedStringUtil;

/**
 * URIs
 */
public final class XXURI {

  public static final XXURI SINGLETON = new XXURI();


  // Base URI
  public static final String BASE = "/v1";

  // COMMAND
  public static final String C_RENEW = "renew";
  public static final String C_ENCRYPT = "encrypt";
  public static final String C_DECRYPT = "decrypt";

  // Ping
  public static final String PING = BASE + "/ping";

  // App URIs
  public static final String APP = BASE + "/app";
  public static final String APP_CONFIG = APP + "-config";
  public static final String APP_VERSION = APP + "-version";

  public static final String AUTO_LOGIN = BASE + "/auto-login";

  public static final String TIMESTAMP = BASE + "/timestamp";


  // Common (ALL users) URIs
  public static final String RESOURCE_TAGS = BASE + "/resource/tags";
  public static final String DISTANCE_CHECK = BASE + "/distance/check";
  public static final String LOGIN = BASE + "/login";
  public static final String LOGOUT = BASE + "/logout";
  public static final String REGISTRATION = BASE + "/registration";
  public static final String DEREGISTRATION = BASE + "/deregistration";
  public static final String PASSWORD_RESET = BASE + "/password/reset";
  public static final String PASSWORD_CHANGE = BASE + "/password/change";

  // file uri
  public static final String RESOURCE = BASE + "/resource";

  // Image URIs
  public static final String IMAGE = BASE + "/image";

  // User URIs
  public static final String USER_INFO = BASE + "/user/info";
  public static final String USER_ADDRESSES = BASE + "/user/addresses";
  public static final String USER_CREDIT_CARDS = BASE + "/user/credit-cards";
  public static final String USER_PREFERENCE = BASE + "/user/preference";
  public static final String USER_DELETE = BASE + "/user/delete";



  //SubjectAPIKey
  public static final String API_KEY_BASE = BASE + "/apikey";


  // Items URIs
  public static final String ITEMS_PUBLISHED = BASE + "/items/published";

  // Order URIs
  public static final String ORDER = BASE + "/order";
  public static final String ORDER_ALL = BASE + "/order/all";
  public static final String ORDER_DETAILS = BASE + "/order/details";
  public static final String ORDER_STATUS = BASE + "/order/status";


  // Management URIs
  public static final String MANAGEMENT_ORDERS = BASE + "/management/orders";
  public static final String MANAGEMENT_ORDERS_PROCESSING = BASE + "/management/orders/processing";
  public static final String MANAGEMENT_USERS = BASE + "/management/users";
  public static final String MANAGEMENT_SERVICE_PROVIDERS = BASE + "/management/service-providers";
  public static final String MANAGEMENT_INVENTORY = BASE + "/management/inventory";

  // Service Provider URIs
  public static final String SERVICE_PROVIDER_ORDER = BASE + "/service-provider/order/";
  public static final String SERVICE_PROVIDER_ORDER_STATUS =
      BASE + "/service-provider/order/status";

  // Websocket URIs
  public static final String WS_NOTIFICATION = BASE + "/ws/notification";


  private String preURI = "/api";

  private XXURI() {

  }

  public void setPreURI(String uri) {
    preURI = SharedStringUtil.trimOrEmpty(uri);
  }

  public String getPreURI() {
    return preURI;
  }

  public String formatURI(String postURI) {
    return SharedStringUtil.concat(preURI, postURI, "/");
  }

}