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

import org.zoxweb.server.http.HTTPRequestAttributes;
import org.zoxweb.server.io.FileInfoStreamSource;
import org.zoxweb.shared.data.FileInfoDAO;
import org.zoxweb.shared.security.AccessException;
import org.zoxweb.shared.security.AuthenticationHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public interface HTTPDownloadHandler
    extends AuthenticationHandler<HttpServletRequest, HttpServletResponse>
{

	/**
	 * Locate the file info source
	 * @param request http request
	 * @param attributes the request attributes
	 * @return the stream source
	 * @throws AccessException if the current subject has no permission
	 * @throws IOException IO error
	 */
	FileInfoStreamSource lookupFileInfoSource(HttpServletRequest request, HTTPRequestAttributes attributes)
        throws AccessException, IOException;
	
	/**
	 * Update the file info dao
	 * @param fileInfo to be updated
	 * @throws AccessException if the subject user has no permission
	 * @throws IOException IO error
	 */
	 void updatedFileInfoDAO(FileInfoDAO fileInfo) 
         throws AccessException, IOException;
	
}
