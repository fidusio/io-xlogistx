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

import org.apache.shiro.subject.Subject;
import org.zoxweb.shared.util.SUS;

import javax.websocket.Session;

public class ShiroWebSocketSession
{
	private final Subject subject;
	private final Session session;
	
	public ShiroWebSocketSession(Session session, Subject subject)
    {
		SUS.checkIfNulls("Null Parameter", session, subject);
		this.session = session;
		this.subject = subject;
	
	}

	public final Subject getSubject()
    {
		return subject;
	}

	public final Session getSession()
    {
		return session;
	}
	
//	public  void sendText(String txt) throws IOException
//	{
//		session.getBasicRemote().sendText(txt);
//	}

}