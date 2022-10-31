/*
 * Copyright (c) 2012-2017 ZoxWeb.com LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package io.xlogistx.http.servlet.shiro;


import org.zoxweb.server.logging.LogWrapper;

import javax.websocket.HandshakeResponse;
import javax.websocket.server.HandshakeRequest;
import javax.websocket.server.ServerEndpointConfig;


public class ShiroWebSocketSessionConfigurator
    extends ServerEndpointConfig.Configurator
{
    public static final String HTTP_SESSION = "http_session";
    @SuppressWarnings("unused")
    public final static LogWrapper log = new LogWrapper(ShiroWebSocketSessionConfigurator.class.getName());
    @Override
    public void modifyHandshake(ServerEndpointConfig config, HandshakeRequest request, HandshakeResponse response)
    {
    	if (request.getHttpSession() != null)
    		config.getUserProperties().put(HTTP_SESSION, request.getHttpSession());
    }

//    @Override
//    public List<Extension> getNegotiatedExtensions(List<Extension> installed,
//                                                   List<Extension> requested)
//    {
//        log.info("installed:" + toString(installed));
//        log.info("requested:" + toString(requested));
//        return installed;
//    }


//    private static String toString(List<Extension> ext)
//    {
//        StringBuilder sb = new StringBuilder();
//        for (Extension e : ext)
//        {
//            sb.append(e.getName());
//            sb.append(", ");
//        }
//
//        return sb.toString();
//    }
}