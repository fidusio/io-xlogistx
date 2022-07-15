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
package io.xlogistx.http.servlet;

import io.xlogistx.common.data.Challenge;
import io.xlogistx.common.image.ImageInfo;
import io.xlogistx.common.image.TextToImage;

import org.zoxweb.server.http.HTTPRequestAttributes;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.util.*;


import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.awt.*;
import java.io.IOException;

import java.util.Map;
import java.util.UUID;
import java.util.logging.Logger;

@SuppressWarnings("serial")
public class HTTPCaptchaServlet
	extends HttpServlet
{
	private static final Logger log = Logger.getLogger(HTTPCaptchaServlet.class.getName());

	
	
	public void doGet(HttpServletRequest req, HttpServletResponse resp)
			  throws ServletException, IOException 
	{
//		int num = Math.abs(sr.nextInt() % 100000);
//		String text = SharedStringUtil.spaceChars("" + num, SharedStringUtil.repeatSequence(" ", num % 4));

//		HTTPRequestAttributes hra = (HTTPRequestAttributes) req.getAttribute(HTTPRequestAttributes.HRA);
		Challenge.Type ct = Challenge.Type.values()[Math.abs(Challenge.SR.nextInt() % Challenge.Type.values().length)];
		int power = 0;


		HTTPRequestAttributes hra = HTTPServletUtil.extractRequestAttributes(req);
		ArrayValues<GetNameValue<String>> formData = hra.getParameters();
		GetNameValue<String> typeParam = formData.get("type");
		if(typeParam != null && typeParam.getValue() != null)
		{
			Challenge.Type typeValue = SharedUtil.lookupEnum(typeParam.getValue(), Challenge.Type.values());
			if(typeValue != null)
			{
				ct = typeValue;
			}
		}

		GetNameValue<String> powerParam = formData.get("power");
		if(powerParam != null && powerParam.getValue() != null)
		{
			try
			{
				power = Integer.parseInt(powerParam.getValue());
			}
			catch(Exception e)
			{

			}
		}

		if(power < 2)
		{
			switch(ct)
			{
				case ADDITION:
				case SUBTRACTION:
					power = 2;
					break;
				case CAPTCHA:
					power = 5;
					break;
			}
		}



		Challenge challenge = Challenge.generate(ct, power, UUID.randomUUID().toString());
		ImageInfo imageInfo = TextToImage.textToImage( challenge.format() + " ", "gif", new Font("Arial", Font.ITALIC, 18), Color.BLUE, challenge.getId());
		resp.setContentType("image/"+imageInfo.format);
		resp.addHeader("Captcha-Id", imageInfo.id);
		resp.addHeader("Access-Control-Allow-Origin", "*");
		resp.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
		resp.setHeader("Access-Control-Expose-Headers", "Captcha-Id");
		resp.setContentLength(imageInfo.data.available());
		IOUtil.relayStreams(imageInfo.data, resp.getOutputStream(), true);
		Map<String, Challenge> captchaMap = ResourceManager.SINGLETON.lookup(Challenge.CAPTCHA);
		if(captchaMap != null)
		{
			captchaMap.put(challenge.getId(), challenge);
			//
			TaskUtil.getDefaultTaskScheduler().queue(Const.TimeInMillis.MINUTE.MILLIS*30,()->{

				Challenge c = captchaMap.remove(challenge.getId());
				log.info("Challenge clean up: " + c);
			});
		}

		// cache.put(uuid, num
		// )


		log.info("Result: " + challenge.getResult() + " ID:" + imageInfo.id);
	}

	
	
	
}
