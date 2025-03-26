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
package io.xlogistx.http.servlet.filters;

import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.util.SharedStringUtil;

import javax.servlet.*;
import java.io.IOException;

public class EncodingFilter
	implements Filter
{

	public static final LogWrapper log = new LogWrapper(EncodingFilter.class).setEnabled(true);
	
	private String encoding = SharedStringUtil.UTF_8;

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
        throws IOException, ServletException
	{
		request.setCharacterEncoding(encoding);
		filterChain.doFilter(request, response);
	}

	public void init(FilterConfig filterConfig)
        throws ServletException
	{
		String encodingParam = filterConfig.getInitParameter("encoding");

		if (encodingParam != null)
		{
			encoding = encodingParam;
		}

		if(log.isEnabled()) log.getLogger().info("Encoding:" + encoding);
	}

	public void destroy()
	{

	}

}