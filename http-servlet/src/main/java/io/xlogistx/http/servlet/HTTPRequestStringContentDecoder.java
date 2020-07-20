package io.xlogistx.http.servlet;

import org.zoxweb.server.io.IOUtil;
import org.zoxweb.shared.util.OutputDataDecoder;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class HTTPRequestStringContentDecoder
implements OutputDataDecoder<String>
{
	private HttpServletRequest req;
	private boolean decoded = false;
	public HTTPRequestStringContentDecoder(HttpServletRequest req)
	{
		this.req = req;
	}

	@Override
	public String decode() 
	{
		// TODO Auto-generated method stub
		if (!decoded)
		{
			synchronized(this)
			{
				if(!decoded)
				{
					decoded = true;
					try
					{
						return IOUtil.inputStreamToString(req.getInputStream(), false);
					}
					catch(IOException e)
					{
						
					}
				}
			}
		}
		return null;
	}

}
