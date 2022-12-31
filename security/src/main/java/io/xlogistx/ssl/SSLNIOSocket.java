/*
 * Copyright (c) 2017-2021 XlogistX.IO Inc.
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
package io.xlogistx.ssl;

import io.xlogistx.common.fsm.*;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.logging.LoggerUtil;
import org.zoxweb.server.net.NIOChannelCleaner;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.net.ProtocolHandler;
import org.zoxweb.server.net.SessionCallback;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.security.SSLContextInfo;
import org.zoxweb.server.task.TaskCallback;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.net.InetSocketAddressDAO;
import org.zoxweb.shared.util.ParamUtil;
import org.zoxweb.shared.util.SharedUtil;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.AbstractSelectableChannel;

import static io.xlogistx.ssl.SSLStateMachine.SessionState.POST_HANDSHAKE;


public class SSLNIOSocket
    extends ProtocolHandler
{


	private static class PostHandshake extends TriggerConsumer<SSLSessionConfig>
	{

		private final SSLNIOSocket sslns;
		PostHandshake(SSLNIOSocket sslns)
		{
			super(POST_HANDSHAKE);
			this.sslns = sslns;
		}
		@Override
		public void accept(SSLSessionConfig config)
		{
			if(config.remoteAddress != null && config.inRemoteData == null)
			{
				synchronized (config)
				{
					if(config.inRemoteData == null)
					{
						try
						{
							config.inRemoteData = ByteBufferUtil.allocateByteBuffer(ByteBufferUtil.BufferType.DIRECT, ByteBufferUtil.DEFAULT_BUFFER_SIZE);
							config.remoteChannel = SocketChannel.open((new InetSocketAddress(config.remoteAddress.getInetAddress(), config.remoteAddress.getPort())));
							sslns.getSelectorController().register(null, config.remoteChannel, SelectionKey.OP_READ, sslns, false);
						}
						catch(Exception e)
						{
							if (log.isEnabled()) log.getLogger().info("" + e);
							if (log.isEnabled()) log.getLogger().info("connect to " + config.remoteAddress + " FAILED");
							config.close();
						}
					}
				}
			}
		}
	}


	private static class TunnelCallback extends SSLSessionCallback
	{
		@Override
		public void exception(Exception e) {
			// exception handling
			//e.printStackTrace();
			if (log.isEnabled()) log.getLogger().info(e + "");
		}

		@Override
		public void accept(ByteBuffer buffer) {
			// data handling
			if(buffer != null)
			{
				try
				{
					ByteBufferUtil.smartWrite(null, getConfig().remoteChannel, buffer);
				}
				catch(IOException e)
				{
					if (log.isEnabled()) log.getLogger().info(e+"");
					// we should close
					IOUtil.close(get());
				}

			}
		}
	}




    public static final LogWrapper log = new LogWrapper(SSLNIOSocket.class).setEnabled(false);

	private SSLStateMachine sslStateMachine = null;
	private SSLSessionConfig config = null;
	final public InetSocketAddressDAO remoteAddress;
	final private SSLContextInfo sslContext;
	private final SessionCallback sessionCallback;

	public SSLNIOSocket(SSLContextInfo sslContext, InetSocketAddressDAO ra)
	{

		this(sslContext, ra, new TunnelCallback());
	}

	public SSLNIOSocket(SSLContextInfo sslContext, InetSocketAddressDAO ra, SSLSessionCallback sessionCallback)
	{
		SharedUtil.checkIfNulls("context  can't be null", sslContext);
		this.sslContext = sslContext;
		remoteAddress = ra;
		if(remoteAddress != null && sessionCallback == null)
		{
			this.sessionCallback = new TunnelCallback();
		}
		else
			this.sessionCallback = sessionCallback;

		SharedUtil.checkIfNulls("Session callback can't be null", this.sessionCallback);
	}
	
	@Override
	public String getName()
	{
		return "SSLNIOSocket";
	}

	@Override
	public String getDescription() 
	{
		return "SSL NIO Server Socket";
	}

	@Override
	public void close()
    {
		if(sslStateMachine != null)
			config.close();

	}

	@Override
	public  void accept(SelectionKey key)
	{
		if (log.isEnabled()) log.getLogger().info("Start of Accept SSLNIOSocket");
		try
    	{
			// first call
//			if(sslStateMachine.getCurrentState().getName().equals(StateInt.States.INIT.getName()) &&
//					key.channel() == config.sslChannel)
//			{
//				config.beginHandshake(false);
//				sessionCallback.setConfig(config);
//			}

			if(!config.hasBegan.get())
				config.beginHandshake(false);
				//sessionCallback.setConfig(config);




			if (log.isEnabled()) log.getLogger().info("AcceptNewData: " + key);
			if (key.channel() == config.sslChannel && key.channel().isOpen())
			{
				sslStateMachine.publishSync(new Trigger<TaskCallback<ByteBuffer, SSLChannelOutputStream>>(this,
						SharedUtil.enumName(config.getHandshakeStatus()),
						null,
						sessionCallback));
			}
			else if (key.channel() == config.remoteChannel && key.channel().isOpen())
			{
				int bytesRead = config.remoteChannel.read(config.inRemoteData);
				if (bytesRead == -1)
				{
					if (log.isEnabled()) log.getLogger().info("SSLCHANNEL-CLOSED-NEED_UNWRAP: "+ config.getHandshakeStatus()	+ " bytesread: "+ bytesRead);
					config.close();
					return;
				}
				config.sslOutputStream.write(config.inRemoteData);
			}
    	}
    	catch(Exception e)
    	{
    		e.printStackTrace();
    		close();
			if (log.isEnabled()) log.getLogger().info(System.currentTimeMillis() + ":Connection end " + key + ":" + key.isValid() + " " + TaskUtil.availableThreads(getExecutor()));
    	}
		if (log.isEnabled()) log.getLogger().info( "End of SSLNIOSocket-ACCEPT  available thread:" + TaskUtil.availableThreads(getExecutor()));
	}




	protected void acceptConnection(NIOChannelCleaner ncc, AbstractSelectableChannel asc, boolean isBlocking) throws IOException {
		// must be modified do the handshake
		//((SocketChannel)asc).setOption(StandardSocketOptions.TCP_NODELAY, true);
    	sslStateMachine = SSLStateMachine.create(sslContext, null);
		config = sslStateMachine.getConfig();
		if(remoteAddress != null)
			sslStateMachine.register(new State("connect-remote").register(new PostHandshake(this)));
    	config.selectorController = getSelectorController();
		config.sslChannel = (SocketChannel) asc;
		config.remoteAddress = remoteAddress;
		config.sslOutputStream = new SSLChannelOutputStream(config, 512 );
		sessionCallback.setConfig(config);
		sslStateMachine.start(true);
		getSelectorController().register(ncc,  asc, SelectionKey.OP_READ, this, isBlocking);


	}






	@SuppressWarnings("resource")
    public static void main(String... args)
    {

		TaskUtil.setThreadMultiplier(8);
		TaskUtil.setMaxTasksQueue(2048);
    	LoggerUtil.enableDefaultLogger("io.xlogistx");
		try
		{
			ParamUtil.ParamMap params = ParamUtil.parse("-", args);
			int port = params.intValue("-port");
			String keystore = params.stringValue("-keystore");
			String ksType = params.stringValue("-kstype");
			String ksPassword = params.stringValue("-kspassword");
			boolean dbg = params.nameExists("-dbg");
			String ra =  params.stringValue("-ra", true);
			InetSocketAddressDAO remoteAddress = ra != null ? new InetSocketAddressDAO(ra) : null;

			if(dbg)
			{
				StateMachine.log.setEnabled(true);
				TriggerConsumer.log.setEnabled(true);
				SSLSessionConfig.log.setEnabled(true);
			}




			//TaskUtil.setThreadMultiplier(4);
			SSLContext sslContext = CryptoUtil.initSSLContext(null, null, IOUtil.locateFile(keystore), ksType, ksPassword.toCharArray(), null, null ,null);

			new NIOSocket(new InetSocketAddress(port), 512, new SSLNIOSocketFactory(new SSLContextInfo(sslContext), remoteAddress), TaskUtil.getDefaultTaskProcessor());
		}
		catch(Exception e)
		{
			e.printStackTrace();
			TaskUtil.getDefaultTaskScheduler().close();
			TaskUtil.getDefaultTaskProcessor().close();
		}
	}


}