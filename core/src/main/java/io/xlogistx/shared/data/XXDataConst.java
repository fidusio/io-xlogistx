package io.xlogistx.shared.data;

import org.zoxweb.shared.util.GetName;

/**
 * Created on 7/16/17
 */
public class XXDataConst {

  public enum AppKey
      implements GetName {

    SUBJECT_API_KEY("subject_api_key"),
    USER_INFO_DAO("user_info_dao"),
    APP_DEVICE_DAO("app_device_dao"),
    CURRENT_PASSWORD("current_password"),
    NEW_PASSWORD("new_password"),
    DOMAIN_ID("domain_id"),
    APP_ID("app_id");

    private String name;

    AppKey(String name) {
      this.name = name;
    }

    @Override
    public String getName() {
      return name;
    }
  }

  private XXDataConst() {

  }


}
