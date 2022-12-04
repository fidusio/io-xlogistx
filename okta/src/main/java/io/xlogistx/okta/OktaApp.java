package io.xlogistx.okta;

import io.xlogistx.okta.api.*;
import org.zoxweb.server.http.HTTPCall;
import org.zoxweb.server.security.BCrypt;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.data.Range;

import org.zoxweb.shared.http.HTTPAuthScheme;
import org.zoxweb.shared.http.HTTPAuthorizationToken;
import org.zoxweb.shared.util.*;

import java.util.Arrays;
import java.util.Date;
import java.util.UUID;
import java.util.logging.Logger;

import static io.xlogistx.okta.api.OktaCache.CacheType.RATE_CONTROLLER;


public class OktaApp {

    private static final Logger log = Logger.getLogger(OktaApp.class.getName());
    private static void error(String message, Exception e)
    {

        System.err.println("Error: " + message);
        System.err.println("Usage: COMMAND url=https://domain.okta.com token=003XQTwiBMPlmGes7uQAE31YogTj_kYWNNfkSpBh enableHttp=true [threadCount=64]:");
        System.err.println("\tCreate username=email@domain.com password=UserPassword!23 firstname=John lastname=SMITH {brypt=true}");
        System.err.println("\tLogin username=email@domain.com password=UserPassword!23");
        System.err.println("\tLookup username=email@domain.com");
        System.err.println("\tDelete username=email@domain.com");
        System.err.println("\tUpdatePassword username=email@domain.com password=CurrentPassword newpassword=NewPassword");
        System.err.println("\tListGroupUsers group=groupName {deleteGroupUsers=true}");
        System.err.println("\tGenUsers count=100 username={countIndex}-email@Domain.com password=UserPassword!23 firstname={countIndex}-John lastname={countIndex}-SMITH {brypt=true} groups=groupName rate=250/min");
        System.err.println("\tGenLogins username=joe@nodomain.com password=Password  count=2000 rate=2200/min range=[60,10000]");

        if(e != null)
        {
            e.printStackTrace();
        }
        System.exit(-1);
    }
    public static void main(String ...args) {


        OktaAdapter oktaAdapter =  new DefaultOktaAdapter();
        try {


            ParamUtil.ParamMap params = ParamUtil.parse("=", args);

            log.info("" + params);


            String url = params.stringValue("url");
            int threadCount = params.intValue("threadCount", 0);

            String token = params.stringValue("token");
            String command = params.stringValue(0).toUpperCase();
            boolean enabledHttp = params.booleanValue("enableHttp", true);
            String userName = params.stringValue("username", null, true);
            String email = params.stringValue("email", null, true);
            String newUserName = params.stringValue("newUserName", null, true);

            String users = params.stringValue("users", null, true);
            String password = params.stringValue("password", null, true);
            String newPassword = params.stringValue("newPassword", null, true);
            String firstName = params.stringValue("firstname", null, true);
            String lastName = params.stringValue("lastname", null, true);
            String mobilePhone = params.stringValue("mobilePhone", null, true);
            boolean active = params.booleanValue("active", true);
            boolean bCrypt = params.booleanValue("bcrypt", true);
            String rangeParam = params.stringValue("range", null, true);


            String match = params.stringValue("match", null, true);
            int bCryptLog = 10;
            int count = params.intValue("count", 1);
            String ratePerUnit = params.stringValue("rate", "50/min");
            //String search = params.stringValue("search", null, true);
            String group = params.stringValue("group", null, true);
            boolean deleteGroupUsers = params.booleanValue("deleteGroupUsers", true);
            String[] groups = (params.stringValue("groups", null, true) != null) ? SharedStringUtil.parseString(params.stringValue("groups", null, true), ",", true) : null;

//            TaskUtil.setMaxTasksQueue(2000);
            if(threadCount > 0)
                TaskUtil.setTaskProcessorThreadCount(threadCount);
//            TaskUtil.getDefaultTaskScheduler();
            OktaCache.SINGLETON.getCache().addObject(RATE_CONTROLLER, new RateController("app",ratePerUnit));



            // create a adapter
            oktaAdapter.setURL(url)
                    .setHTTPAuthorization(new HTTPAuthorizationToken(HTTPAuthScheme.SSWS, token))
                    .enableHttpCalling(enabledHttp);

            DefaultOktaAdapter.log.setEnabled(true);

            long ts = System.currentTimeMillis();
            switch (command) {
                case "CREATE": {
                    SharedUtil.checkIfNulls("CREATE Missing parameters username, password, firstName, lastName", userName, password, firstName, lastName);
                    OktaUser oktaUser = new DefaultOktaUser().setOktaProfile(new DefaultOktaUserProfile());

                    oktaUser.getOktaProfile().setEmail(userName)
                            .setUserName(userName)
                            .setFirstName(firstName)
                            .setLastName(lastName)
                            .setMobilePhone(mobilePhone)
                            .setUUID(UUID.randomUUID().toString());
                    if (bCrypt) {
                        oktaUser.setCredentials(new OktaCredentials().setBCrypt(BCrypt.hashpw(password, BCrypt.gensalt(bCryptLog))));
                    } else {
                        oktaUser.setCredentials(new OktaCredentials().setPlainPassword(password));
                    }
                    OktaUser oktafied = oktaAdapter.registerUser(oktaUser, active, groups);
                    log.info("User created " + oktafied);

                }
                break;
                case "LOGIN": {
                    SharedUtil.checkIfNulls("LOGIN Missing parameters username, password", userName, password);
                    NVGenericMap loginResponse = oktaAdapter.userLogin(userName, password);
                    log.info(userName + " login successfully\n" + loginResponse);
                }
                break;

                case "GENLOGINS": {

                    if(rangeParam != null)
                    {
                        SharedUtil.checkIfNulls("GenLogins Missing parameters userName postfix or password", userName, password);
                        Range<Integer> usersRange = Range.toRange(rangeParam);
                        for(int i = 0; i < count;)
                        {
                            for (int j = usersRange.getStart(); j < usersRange.getEnd() && i < count; j++,i++)
                            {
                                int val = j;
                                int countIndex = i;
                                TaskUtil.getDefaultTaskScheduler().queue(OktaCache.SINGLETON.rateController("app").nextDelay(), ()->{
                                    String userToAuthN = val + "-" + userName;

                                    try {
                                        oktaAdapter.userLogin(userToAuthN, password);
                                        if(countIndex %200 == 0)
                                            log.info("[" + countIndex + "]SUCCESS : " + userToAuthN + " login successful " + TaskUtil.info());
                                        OktaCache.SINGLETON.rateCounter(OktaCache.RateCount.SUCCESS).register(0, 1);
                                    } catch (Exception e) {
                                        OktaCache.SINGLETON.rateCounter(OktaCache.RateCount.FAILED).register(0, 1);
                                        log.info("[" + countIndex + "]FAILED : " + userToAuthN + "  OktaAPIRate: " + oktaAdapter.getCurrentAPIRate() + "\n" + e +"\n" +
                                                TaskUtil.info());
                                    }


                                });
                            }
                        }

                    }
                    else
                    {
                        SharedUtil.checkIfNulls("GenLogins Missing parameters users=user1:password1,user2:password2...", users);
                        // parser user set as user=user1:password1,user2:password2...

                        String[] userNames = users.split(",");
                        String[] passwords = new String[userNames.length];
                        int size = 0;
                        for(String oneUser : userNames)
                        {
                            String[] parsedParam = oneUser.split(":");
                            if(parsedParam.length == 2)
                            {
                                userNames[size] = parsedParam[0];
                                passwords[size++] = parsedParam[1];
                            }
                        }

                        for(int i= 0; i<count;) {
                            for (int j = 0; j < size && i < count; j++, i++) {
                                int userIndex = j;
                                int countIndex = i;
                                TaskUtil.getDefaultTaskScheduler().queue(OktaCache.SINGLETON.rateController("app").nextDelay(), () -> {
                                    try {
                                        oktaAdapter.userLogin(userNames[userIndex], passwords[userIndex]);
        //                                    if(countIndex %1000 == 0)
                                        log.info("[" + countIndex + "]SUCCESS : " + userNames[userIndex] + " login successful");
                                        OktaCache.SINGLETON.rateCounter(OktaCache.RateCount.SUCCESS).register(0, 1);
                                    } catch (Exception e) {
                                        OktaCache.SINGLETON.rateCounter(OktaCache.RateCount.FAILED).register(0, 1);
                                        log.info("[" + countIndex + "]FAILED : " + userNames[userIndex] + "  OktaAPIRate: " + oktaAdapter.getCurrentAPIRate() + "\n" + e);
                                    }
                                });
                            }
                        }
                    }
                }

                break;

                case "LOOKUP": {
                    SharedUtil.checkIfNulls("LOGIN Missing parameters username, password", userName);

                    long userNameTS = System.currentTimeMillis();
                    OktaUser user = oktaAdapter.lookupUser(userName);
                    userNameTS = System.currentTimeMillis() - userNameTS;
                    ///OktaAdapter.log.setEnabled(true);
                    long okaIdTS = System.currentTimeMillis();
                    user = oktaAdapter.lookupUser(user.getOktaId());
                    okaIdTS = System.currentTimeMillis() - okaIdTS;

                    log.info(userName + " lookup successfully: " + user + "\nIt took username lookup: " +
                            Const.TimeInMillis.toString(userNameTS) + " oktaId lookup: " + Const.TimeInMillis.toString(okaIdTS) +
                            "\n" + oktaAdapter.getCurrentAPIRate());
                }
                break;
                case "DELETE": {

                    SharedUtil.checkIfNulls("LOGIN Missing parameters username", userName);
                    oktaAdapter.deleteUser(userName);
                    log.info(userName + " deleted successfully\n");
                }
                break;
                case "UPDATEPASSWORD": {
                    SharedUtil.checkIfNulls("PASSWORDUPDATE Missing parameters username, password,newPassword", userName, password, newPassword);
                    OktaUser user = oktaAdapter.userUpdatePassword(userName, password, newPassword);
                    log.info(userName + " password update successful\n" + user);
                }
                break;


                case "UPDATEUSER": {
                    SharedUtil.checkIfNulls("UPDATEUSER Missing parameters username", userName);
                    OktaUser currentUser = oktaAdapter.lookupUser(userName);
                    OktaUser toUpdate = new DefaultOktaUser();
                    toUpdate.setOktaId(currentUser.getOktaId()).setOktaProfile(new DefaultOktaUserProfile());

                    if (newUserName != null)
                        toUpdate.getOktaProfile().setUserName(newUserName);

                    if (email != null)
                        toUpdate.getOktaProfile().setEmail(email);

                    if (firstName != null)
                        toUpdate.getOktaProfile().setFirstName(firstName);

                    if (lastName != null)
                        toUpdate.getOktaProfile().setLastName(lastName);

                    if (newPassword != null) {
                        toUpdate.setCredentials(new OktaCredentials());
                        if (bCrypt)
                            toUpdate.getCredentials().setBCrypt(BCrypt.hashpw(password, BCrypt.gensalt(bCryptLog)));
                        else
                            toUpdate.getCredentials().setPlainPassword(newPassword);
                    }

                    log.info("UPDATEUSER successful: " + oktaAdapter.updateOktaUser(toUpdate));


                }
                break;

                case "LOOKUPUSER": {
                    SharedUtil.checkIfNulls("LOOKUPUSER Missing parameters username, password,newPassword", userName);
                    OktaUser user = oktaAdapter.lookupUser(userName);
                    log.info("User found " + user);

                }
                break;

                case "LISTGROUPUSERS": {
                    SharedUtil.checkIfNulls("LISTGROUPUSERS Missing parameters group", group);

                    boolean loop = true;
                    while (loop) {
                        OktaUser[] oktaUsers = oktaAdapter.listGroupUsers(group);
                        log.info(Arrays.toString(oktaUsers));


                        if (!deleteGroupUsers || oktaUsers == null || oktaUsers.length == 0)
                            loop = false;
                        else {
                            loop = match == null;
                            count += oktaUsers.length;
                            // delete group
                            for (OktaUser user : oktaUsers) {
                                boolean delete = true;
                                if (match != null) {
                                    delete = user.getOktaProfile().getUserName().contains(match);
                                }


                                if (delete)
                                    TaskUtil.getDefaultTaskScheduler().queue(OktaCache.SINGLETON.rateController("app").nextDelay(), () -> {
                                        try {
                                            oktaAdapter.deleteUser(user);
                                            log.info("User " + user.getOktaProfile().getUserName() + " deleted\navailable threads " +
                                                    TaskUtil.info());
                                            OktaCache.SINGLETON.rateCounter(OktaCache.RateCount.SUCCESS).register(0, 1);
                                        } catch (Exception e) {

                                            log.info("************FAILED DELETE******* for ser " + SharedUtil.toCanonicalID(',',user.getOktaProfile().getUserName(), user.getStatus()) + " available threads " +
                                                    TaskUtil.info());
                                            log.info("API RATE: " + oktaAdapter.getCurrentAPIRate());
                                            OktaCache.SINGLETON.rateCounter(OktaCache.RateCount.FAILED).register(0, 1);
                                            e.printStackTrace();
                                            //throw new RuntimeException(e);
                                        }
                                    });
                            }
                            TaskUtil.waitIfBusy(100);
                        }
                    }
                }
                break;

                case "LISTGROUPS": {

                    OktaGroup[] oktaGroups = oktaAdapter.listGroups();
                    log.info(Arrays.toString(oktaGroups));


                }
                break;

                case "GENUSERS": {
                    Date startDate = new Date();
                    long genTS = System.currentTimeMillis();
                    OktaCredentials credentials = new OktaCredentials();
                    if (bCrypt) {
                        credentials.setBCrypt(BCrypt.hashpw(password, BCrypt.gensalt(bCryptLog)));
                    } else {
                        credentials.setPlainPassword(password);
                    }
                    log.info("Start time " + new Date());

                    for (int i = 0; i < count; i++) {
                        int val = i;
                        OktaUser oktaUser = new DefaultOktaUser().setOktaProfile(new DefaultOktaUserProfile());

                        oktaUser.getOktaProfile().setEmail(val + "-" + userName)
                                .setUserName(val + "-" + userName)
                                .setFirstName(val + "-" + firstName)
                                .setLastName(val + "-" + lastName)
                                .setUUID(UUID.randomUUID().toString());
                        oktaUser.setCredentials(credentials);
                        if (OktaCache.SINGLETON.rateController("app").getTPSAsLong() != 0) {
                            TaskUtil.getDefaultTaskScheduler().queue(OktaCache.SINGLETON.rateController("app").nextDelay(), () -> {

                                try {
                                    OktaUser oktafied = oktaAdapter.registerUser(oktaUser, active, groups);
                                    if (oktafied != null && val % 200 == 0)
                                        log.info("GENUSERS OktaFiedUser : " +
                                                SharedUtil.toCanonicalID(',' ,oktafied.getOktaProfile().getUserName() ,  oktafied.getOktaId()) + "\n"  +  TaskUtil.info());

                                    OktaCache.SINGLETON.rateCounter(OktaCache.RateCount.SUCCESS).register(0, 1);
                                } catch (Exception e) {
                                    OktaCache.SINGLETON.rateCounter(OktaCache.RateCount.FAILED).register(0, 1);

                                    e.printStackTrace();
                                }
                            });
                        } else {
                            TaskUtil.getDefaultTaskProcessor().execute(() -> {
                                try {
                                    OktaUser oktafied = oktaAdapter.registerUser(oktaUser, active, groups);
                                    if (oktafied != null)
                                        log.info("GENUSERS OktaFiedUser : " +
                                                SharedUtil.toCanonicalID(',' ,oktafied.getOktaProfile().getUserName() ,  oktafied.getOktaId()) + "\n"  +  TaskUtil.info());
                                    OktaCache.SINGLETON.rateCounter(OktaCache.RateCount.SUCCESS).register(0, 1);
                                } catch (Exception e) {
                                    OktaCache.SINGLETON.rateCounter(OktaCache.RateCount.SUCCESS).register(0, 1);
                                    log.info("************FAILED GENUSERS******* for  " + SharedUtil.toCanonicalID(',',oktaUser.getOktaProfile().getUserName()) + " available threads " +
                                            TaskUtil.info() + " API RATE: " + oktaAdapter.getCurrentAPIRate());
                                    e.printStackTrace();
                                }
                            });
                        }
                    }


                    genTS = TaskUtil.waitIfBusy(50) - genTS;
                    RateCounter success = OktaCache.SINGLETON.rateCounter(OktaCache.RateCount.SUCCESS).register(genTS, 0);
                    RateCounter failed = OktaCache.SINGLETON.rateCounter(OktaCache.RateCount.FAILED);

                    log.info("GENUSERS took " + Const.TimeInMillis.toString(genTS) + " to create " + count + " users at rate: " + success.rate(Const.TimeInMillis.SECOND.MILLIS) + "/tps");
                    log.info("Success " + success.getCounts() + " Failed " + failed.getCounts());
                    log.info("Start time " + startDate + "  End time " + new Date());


                }
                break;

                default:
                    error("missing command", null);


            }



            ts = TaskUtil.waitIfBusy(50) - ts;

            RateCounter total = new RateCounter("total");
            total.register(ts, count);


            RateCounter success = OktaCache.SINGLETON.rateCounter(OktaCache.RateCount.SUCCESS);
            RateCounter failed = OktaCache.SINGLETON.rateCounter(OktaCache.RateCount.FAILED);

            log.info("***["+ command + "]*** took " + Const.TimeInMillis.toString(total.getDeltas()) + " transactions " + total.getCounts()
                     + " success: " + success.getCounts() + " failed: " + failed.getCounts()
                     + "\n stats " + total.rate(Const.TimeInMillis.SECOND.MILLIS) + "/tps"
                     + " " + total.rate(Const.TimeInMillis.MINUTE.MILLIS) + "/tpm " + HTTPCall.HTTP_CALLS
                     +"\n" + TaskUtil.info()
            );


        } catch (Exception e) {
            error("Processing error", e);
        }

        TaskUtil.waitIfBusyThenClose(50);

        log.info("Finished total GSONDefault calls " + GSONUtil.getJSONDefaultCount());
        log.info("OktaAPIRate: " + oktaAdapter.getCurrentAPIRate());

    }
}
