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
package io.xlogistx.common.net;

import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.net.*;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.net.InetSocketAddressDAO;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.logging.Logger;


public class NIOPlainSocket
    extends ProtocolProcessor
{
    private static final transient Logger log = Logger.getLogger(NIOPlainSocket.class.getName());

	private static boolean debug = false;






	private volatile SocketChannel sourceChannel = null;
	private volatile SelectionKey  sourceSK = null;
	private volatile ByteBuffer sourceBB = ByteBufferUtil.allocateByteBuffer(ByteBufferUtil.BufferType.DIRECT, 1024);



	private final PlainSessionCallback sessionCallback;

	public NIOPlainSocket(PlainSessionCallback psc)
	{
		this.sessionCallback = psc;
	}
	
	@Override
	public String getName()
	{
		return "NIOTunnel";
	}

	@Override
	public String getDescription() 
	{
		return "NIO Tunnel";
	}

	@Override
	public void close() throws IOException
    {
		if(!isClosed.getAndSet(true))
		{
			IOUtil.close(sourceChannel);
			IOUtil.close(sessionCallback.get());
			ByteBufferUtil.cache(sourceBB);
		}
	}


	@Override
	public void accept(SelectionKey key)
	{
		try
    	{

			if(sourceChannel == null)
			{
				synchronized (this) {
					if(sourceChannel == null) {
						sourceChannel = (SocketChannel) key.channel();
						sourceSK = key;
						sessionCallback.setConfig(sourceChannel);
					}
				}

			}







			int read = 0 ;
    		do
            {
				sourceBB.clear();
				read = sourceChannel.read(sourceBB);

    			if (read > 0)
    			{
					sessionCallback.accept(sourceBB);
    			}
    		}
    		while(read > 0);
    		
    		if (read == -1)
    		{
    			if (debug) log.info("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+Read:" + read);

    			close();
    				
    			if (debug) log.info(key + ":" + key.isValid()+ " " + Thread.currentThread() + " " + TaskUtil.getDefaultTaskProcessor().availableExecutorThreads());		
    		}
    	}
    	catch(Exception e)
    	{
    		if (debug) e.printStackTrace();
    		IOUtil.close(this);
    		if (debug) log.info(System.currentTimeMillis() + ":Connection end " + key + ":" + key.isValid()+ " " + Thread.currentThread() + " " + TaskUtil.getDefaultTaskProcessor().availableExecutorThreads());
    		
    	}
	}
	
	@SuppressWarnings("resource")
    public static void main(String... args)
    {
		try
		{
			int index = 0;
			int port = Integer.parseInt(args[index++]);
			Class<? extends PlainSessionCallback> clazz = (Class<? extends PlainSessionCallback>) Class.forName(args[index++]);
			TaskUtil.setThreadMultiplier(8);
			
			
			new NIOSocket(new InetSocketAddress(port), 128, new NIOPlainSocketFactory(clazz), TaskUtil.getDefaultTaskProcessor());
		}
		catch(Exception e)
		{
			e.printStackTrace();
			TaskUtil.getDefaultTaskScheduler().close();
			TaskUtil.getDefaultTaskProcessor().close();
		}
	}

}