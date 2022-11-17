package io.xlogistx.okta.api;


import org.zoxweb.server.http.HTTPCall;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.util.GetNameValue;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.RateCounter;
import org.zoxweb.shared.util.SharedStringUtil;

import java.io.IOException;
import java.util.UUID;



public class DefaultOktaAdapter
    implements OktaAdapter

{




    private String url;
    private HTTPAuthentication httpAuthentication;

    //private boolean httpCallEnabled = true;


    private final OktaAPIRate oktaAPIRate = new OktaAPIRate("Adapter");



    public DefaultOktaAdapter()
    {
    }

    @Override
    public String getURL() {
        return url;
    }

    @Override
    public OktaAdapter setURL(String url) {
        this.url = url;
        return this;
    }

    @Override
    public HTTPAuthentication getHTTPAuthentication() {
        return httpAuthentication;
    }

    @Override
    public OktaAdapter setHTTPAuthentication(HTTPAuthentication httpAuthentication) {
        this.httpAuthentication = httpAuthentication;
        return this;
    }

    @Override
    public OktaUser registerUser(OktaUser user, boolean activate, String ...groups) throws IOException {
        HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, URIs.USERS.getValue() +"?activate=" + activate, HTTPMethod.POST);
        hmci.setAuthentication(getHTTPAuthentication());
        hmci.setContentType("application/json");
        hmci.setAccept("application/json");

        if(user.getOktaProfile().getUUID() == null)
            user.getOktaProfile().setUUID(UUID.randomUUID().toString());
        if(groups != null && groups.length > 0)
        {
            for(String group : groups)
            {

                OktaGroup oktaGroup = OktaCache.SINGLETON.lookupGroup(group);
                if(oktaGroup == null)
                {
                    listGroups();
                    oktaGroup = OktaCache.SINGLETON.lookupGroup(group);
                    if (oktaGroup == null)
                        throw new IllegalArgumentException("Group " + group + " not found");
                }

                user.addToGroupId(oktaGroup.getId());
            }
        }

        hmci.setContent(GSONUtil.toJSONDefault(user));

        return send(hmci, DefaultOktaUser.class);


//        SharedUtil.checkIfNulls("User can't be null", user, user.getOktaProfile(), user.getOktaProfile().getEmail(), user.getOktaProfile().getUserName());
//        Map<String, Object> prop = new HashMap<String, Object>();
//        prop.put("uuid", UUID.randomUUID().toString());
//        prop.put("division", "tank");
//        OktaProfile profile = user.getOktaProfile();
//        User oktaUser = UserBuilder.instance()
//                .setEmail(profile.getEmail())
//                .setLogin(profile.getUserName())
//                .setFirstName(profile.getFirstName())
//                .setLastName(profile.getLastName())
//                .setPassword(user.getCredentials().getPlainPassword().toCharArray())
//                .setActive(true)
//                .setProfileProperties(prop)
//                .buildAndCreate(client);
//
//
//        user.setUUID(oktaUser.getString("uuid"))
//                .setOktaId(oktaUser.getId());


//        return user;
    }

    @Override
    public OktaUser lookupUser(String oktaIdOrUserID) throws IOException {
        HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url,
                URIs.USERS.getValue()+"/" +oktaIdOrUserID,
                HTTPMethod.GET);
        hmci.setContentType("application/json");
        hmci.setAccept("application/json");
        hmci.setAuthentication(getHTTPAuthentication());
        return send(hmci, DefaultOktaUser.class);
    }

    @Override
    public OktaAdapter deleteUser(String username) throws IOException {
        OktaUser user = lookupUser(username);
        return deleteUser(user);
    }


    public OktaAdapter deleteUser(OktaUser oktaUser) throws IOException {

        if(oktaUser.getStatus() != OktaUser.OktaUserStatus.DEPROVISIONED) {
            HTTPMessageConfigInterface hmciDeactivate = HTTPMessageConfig.createAndInit(getURL(),
                    SharedStringUtil.embedText(URIs.USER_DEACTIVATE.getValue(), Token.USERID.getValue(), oktaUser.getOktaId()), HTTPMethod.POST);
            hmciDeactivate.setContentType("application/json");
            hmciDeactivate.setAccept("application/json");
            hmciDeactivate.setAuthentication(getHTTPAuthentication());
            send(hmciDeactivate);

        }


        HTTPMessageConfigInterface hmciDelete = HTTPMessageConfig.createAndInit(getURL(),
                SharedStringUtil.embedText(URIs.USER_DELETE.getValue(), Token.USERID.getValue(), oktaUser.getOktaId()), HTTPMethod.DELETE);
        hmciDelete.setContentType("application/json");
        hmciDelete.setAccept("application/json");
        hmciDelete.setAuthentication(getHTTPAuthentication());

        send(hmciDelete);


        return this;
    }

    @Override
    public OktaUser[] listGroupUsers(String group) throws IOException {
        OktaGroup oktaGroup = OktaCache.SINGLETON.lookupGroup(group);
        if(oktaGroup == null)
        {
            listGroups();
        }
        oktaGroup = OktaCache.SINGLETON.lookupGroup(group);
        if (oktaGroup == null)
            throw new IllegalArgumentException("Group " + group + " not found");

        String url = ((NVGenericMap)oktaGroup.getLinks().get("users")).getValue("href");


        HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, null, HTTPMethod.GET);
        hmci.setContentType("application/json");
        hmci.setAccept("application/json");
        hmci.setAuthentication(getHTTPAuthentication());


        return send(hmci, DefaultOktaUser[].class);
    }


    @Override
    public OktaUser lookupByUUID(String username) {
        return null;
    }

    @Override
    public OktaAdapter deleteByUUID(String username) {
        return null;
    }

    @Override
    public NVGenericMap userLogin(String username, String password) throws IOException {
        HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, URIs.AUTHN.getValue(), HTTPMethod.POST);
        hmci.setContentType("application/json");

        hmci.setAccept("application/json");
        NVGenericMap nvgm = new NVGenericMap();
        nvgm.add("username", username);
        nvgm.add("password", password);
        hmci.setContent(GSONUtil.toJSONDefault(nvgm));

        return send(hmci, NVGenericMap.class);
    }

    @Override
    public OktaUser userUpdatePassword(String userName, String oldPassword, String newPassword) throws IOException {
        String uri = SharedStringUtil.embedText(URIs.USER_CHANGE_PASSWORD.getValue(), Token.USERID, userName);
        HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, uri, HTTPMethod.POST);
        hmci.setContentType("application/json");
        hmci.setAccept("application/json");
        hmci.setAuthentication(getHTTPAuthentication());

        NVGenericMap nvgm = new NVGenericMap();
        NVGenericMap oldPasswordNVM = new NVGenericMap();
        oldPasswordNVM.setName("oldPassword");
        oldPasswordNVM.add("value", oldPassword);
        NVGenericMap newPasswordNVM = new NVGenericMap();
        newPasswordNVM.setName("newPassword");
        newPasswordNVM.add("value", newPassword);

        nvgm.add(oldPasswordNVM);
        nvgm.add(newPasswordNVM);
        hmci.setContent(GSONUtil.toJSONDefault(nvgm));

        return send(hmci, DefaultOktaUser.class);
    }

    @Override
    public OktaUser updatePassword(String oktaId, String newPassword) throws IOException {


        HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, URIs.USERS.getValue()+"/" +oktaId, HTTPMethod.POST);
        hmci.setContentType("application/json");
        hmci.setAccept("application/json");
        hmci.setAuthentication(getHTTPAuthentication());


        OktaUser oktaUser = new DefaultOktaUser().setCredentials(new OktaCredentials());
        oktaUser.getCredentials().setPlainPassword(newPassword);
        String json = GSONUtil.toJSONDefault(oktaUser);
        hmci.setContent(json);
        return send(hmci, DefaultOktaUser.class);
    }

    @Override
    public OktaUser updateOktaUser(OktaUser oktaUser) throws IOException {
        String oktaId = oktaUser.getOktaId() == null ? oktaUser.getOktaProfile().getUserName() : oktaUser.getOktaId();
        HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, URIs.USERS.getValue()+"/" +oktaId, HTTPMethod.POST);
        hmci.setContentType("application/json");
        hmci.setAccept("application/json");
        hmci.setAuthentication(getHTTPAuthentication());
        hmci.setContent(GSONUtil.toJSONDefault(oktaUser));
        return send(hmci, DefaultOktaUser.class);
    }

    @Override
    public boolean isHttpCallingEnabled() {
        return HTTPCall.ENABLE_HTTP.get();
    }

    @Override
    public OktaAdapter enableHttpCalling(boolean stat) {
        HTTPCall.ENABLE_HTTP.set(stat);
        return this;
    }

    private HTTPResponseData send(HTTPMessageConfigInterface hmci) throws IOException
    {
        HTTPResponseData ret = null;


        if (isHttpCallingEnabled())
        {

            try {
                ret = HTTPCall.send(hmci);
                if(ret == null)
                    return null;
                try {
                    oktaAPIRate.setParameters(ret);
                }
                catch (Exception e){ e.printStackTrace();}
                log.info(ret);
            }
            catch (HTTPCallException callException)
            {
                HTTPResponseData errHRD = callException.getResponseData();

                try {
                    oktaAPIRate.setParameters(errHRD);
                }
                catch (Exception e){e.printStackTrace();}
                log.info("Err response ", errHRD);
                if (errHRD != null && errHRD.getData() != null)
                {
                    OktaException toThrow = null;
                    try
                    {
                        toThrow = GSONUtil.fromJSONDefault(errHRD.getData(), OktaException.class);
                        toThrow.setStatus(errHRD.getStatus());
                    }
                    catch(Exception e){
                    }
                    if(toThrow != null)
                        throw toThrow;
                }

                throw  callException;
            }
        }


        return ret;
    }


    private <T> T send(HTTPMessageConfigInterface hmci, Class<T> responseType) throws IOException {
        HTTPResponseData hrd = send(hmci);
        if (hrd != null)
        {
            try {
                return GSONUtil.fromJSONDefault(hrd.getDataAsString(), responseType);
            }
            catch(RuntimeException e)
            {
                e.printStackTrace();

               System.out.println("****************ERROR: \n"+hrd.getDataAsString());
                throw e;
            }
        }
        return null;
    }

    @Override
    public OktaUser[] listUsers(GetNameValue<String>...queries) throws IOException {



        HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, URIs.USERS.getValue(), HTTPMethod.GET);
        //hmci.setContentType("application/json");
        hmci.setAccept("application/json");
        hmci.setAuthentication(getHTTPAuthentication());
        for(GetNameValue<String> gnv : queries)
            hmci.getParameters().add(gnv);

        return send(hmci, DefaultOktaUser[].class);

    }

    @Override
    public synchronized OktaGroup[] listGroups() throws IOException {

        HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, URIs.GROUPS.getValue(), HTTPMethod.GET);
        hmci.setContentType("application/json");
        hmci.setAccept("application/json");
        hmci.setAuthentication(getHTTPAuthentication());


        OktaGroup[] ret = send(hmci, DefaultOktaGroup[].class);
        for(OktaGroup og : ret)
            OktaCache.SINGLETON.addGroup(og);


        return ret;
    }

    @Override
    public OktaAPIRate getCurrentAPIRate() {
        return oktaAPIRate;
    }
}
