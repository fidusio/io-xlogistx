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
import io.xlogistx.common.task.CallbackTask;

import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LoggerUtil;
import org.zoxweb.server.net.DefaultSKController;
import org.zoxweb.server.net.NIOChannelCleaner;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.net.ProtocolProcessor;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.net.InetSocketAddressDAO;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngineResult;
import java.io.IOException;
import java.net.InetSocketAddress;


import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.AbstractSelectableChannel;

import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

import static io.xlogistx.ssl.SSLStateMachine.SessionState.POST_HANDSHAKE;


public class SSLNIOTunnel
    extends ProtocolProcessor
{


	static class RemoteConnect extends TriggerConsumer<Void>
	{
		SSLNIOTunnel sslnt;
		RemoteConnect(SSLNIOTunnel sslnt){
			super(POST_HANDSHAKE);
			this.sslnt = sslnt;
		}
		@Override
		public void accept(Void v) {
			if(sslnt.config.inRemoteData == null)
			{
				synchronized (sslnt.config)
				{
					if(sslnt.config.inRemoteData == null)
					{
						try
						{

							sslnt.config.inRemoteData = ByteBufferUtil.allocateByteBuffer(ByteBufferUtil.BufferType.DIRECT, ByteBufferUtil.DEFAULT_BUFFER_SIZE);
							sslnt.config.remoteChannel = SocketChannel.open((new InetSocketAddress(sslnt.remoteAddress.getInetAddress(), sslnt.remoteAddress.getPort())));
							sslnt.getSelectorController().register(null, sslnt.config.remoteChannel, SelectionKey.OP_READ, sslnt, new DefaultSKController(), false);
						}
						catch(Exception e)
						{
							log.info("" + e);
							log.info("connect to " + sslnt.remoteAddress + " FAILED");
							sslnt.config.close();
						}
					}
				}
			}

		}
	}

	class WrapCallback
	implements CallbackTask<ByteBuffer>
	{
		@Override
		public void exception(Exception e) {
			// exception handling
			e.printStackTrace();
			log.info("Available Threads: " + TaskUtil.availableThreads(getExecutor()));
		}

		@Override
		public void callback(ByteBuffer buffer) {
			// data handling
			if(buffer != null)
			{
				try {
					ByteBufferUtil.smartWrite(config.ioLock, config.sslChannel, buffer);
				} catch (IOException e) {
					e.printStackTrace();
					// we should close
					close();
				}
			}
		}
	}

	class UnwrapCallback
			implements CallbackTask<ByteBuffer>
	{
		@Override
		public void exception(Exception e) {
			// exception handling
			e.printStackTrace();
			log.info("Available Threads: " + TaskUtil.availableThreads(getExecutor()));
		}

		@Override
		public void callback(ByteBuffer buffer) {
			// data handling
			if(buffer != null)
			{
				try{
					ByteBufferUtil.smartWrite(null, config.remoteChannel, buffer);

				}
				catch(IOException e)
				{
					e.printStackTrace();
					// we should close
					close();
				}

			}
		}
	}
    private static final transient Logger log = Logger.getLogger(SSLNIOTunnel.class.getName());

	public static boolean debug = false;


	private final static AtomicLong tunnelCounter = new AtomicLong();

	private SSLStateMachine sslStateMachine = null;
	private SSLSessionConfig config = null;




	final public InetSocketAddressDAO remoteAddress;
	final private SSLContext sslContext;

	private final long id = tunnelCounter.incrementAndGet();
	private final WrapCallback  wrapCallback = new WrapCallback();
	private final UnwrapCallback unwrapCallback = new UnwrapCallback();


	private void info(String str)
	{
		if(debug) log.info("[" + id +"] " +str);
	}

	public SSLNIOTunnel(SSLContext sslContext, InetSocketAddressDAO remoteAddress)
	{
		this.remoteAddress = remoteAddress;
		this.sslContext = sslContext;
	}
	
	@Override
	public String getName()
	{
		return "SSLNIOTunnel";
	}

	@Override
	public String getDescription() 
	{
		return "SSL NIO Tunnel";
	}

	@Override
	public void close()
    {
		if(sslStateMachine != null)
			config.close();

		info("closed:" + remoteAddress);
	}






	@Override
	public  void accept(SelectionKey key)
	{
		info("Start of Accept SSLNIOTUNNEL");
		try
    	{
			// first call
			if(sslStateMachine.getCurrentState().getName().equals(StateInt.States.INIT.getName()) &&
					key.channel() == config.sslChannel)
			{
				config.setUseClientMode(false);
				config.beginHandshake();
//				config.inSSLNetData = ByteBufferUtil.allocateByteBuffer(ByteBufferUtil.BufferType.HEAP, config.getPacketBufferSize());
//				config.outSSLNetData = ByteBufferUtil.allocateByteBuffer(ByteBufferUtil.BufferType.HEAP, config.getPacketBufferSize());
//				config.inAppData = ByteBufferUtil.allocateByteBuffer(ByteBufferUtil.BufferType.HEAP, config.getApplicationBufferSize());
				info("We have a connections <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");

			}



			info("AcceptNewData: " + key);
			if (key.channel() == config.sslChannel && key.channel().isOpen())
			{
				sslStateMachine.publish(new Trigger<CallbackTask<ByteBuffer>>(this, SSLEngineResult.HandshakeStatus.NEED_UNWRAP, null, unwrapCallback));
			}
			else if(key.channel() == config.remoteChannel && key.channel().isOpen())
			{
				sslStateMachine.publish(new Trigger<CallbackTask<ByteBuffer>>(this, SSLEngineResult.HandshakeStatus.NEED_WRAP, null, wrapCallback));
			}

    		

    	}
    	catch(Exception e)
    	{
    		e.printStackTrace();


    		close();

    		log.info(System.currentTimeMillis() + ":Connection end " + key + ":" + key.isValid() + " " + TaskUtil.availableThreads(getExecutor()));
    		
    	}
		info( "End of SSLNIOTUNNEL-ACCEPT  available thread:" + TaskUtil.availableThreads(getExecutor()));
	}




	protected void acceptConnection(NIOChannelCleaner ncc, AbstractSelectableChannel asc, boolean isBlocking) throws IOException {
		// must be modified do the handshake
		//((SocketChannel)asc).setOption(StandardSocketOptions.TCP_NODELAY, true);
    	sslStateMachine = SSLStateMachine.create(sslContext, null);
		config = sslStateMachine.getConfig();
		sslStateMachine.register(new State("connect-remote").register(new RemoteConnect(this)));
    	config.selectorController = getSelectorController();
		config.sslChannel = (SocketChannel) asc;
		sslStateMachine.start(true);
		getSelectorController().register(ncc,  asc, SelectionKey.OP_READ, this, new DefaultSKController(), isBlocking);


	}






	@SuppressWarnings("resource")
    public static void main(String... args)
    {

		TaskUtil.setThreadMultiplier(8);
    	LoggerUtil.enableDefaultLogger("io.xlogistx");
		try
		{
			//SSLContext clientContext = SSLContext.getInstance("TLS",new BouncyCastleProvider());
			//Security.addProvider(new BouncyCastleJsseProvider());
			int index = 0;
			int port = Integer.parseInt(args[index++]);
			InetSocketAddressDAO remoteAddress = new InetSocketAddressDAO(args[index++]);
			String keystore = args[index++];
			String ksType = args[index++];
			String ksPassword = args[index++];
			boolean dbg = (index < args.length);
			if(dbg)
			{
				SSLStateMachine.debug = true;
				ReadyState.debug = true;
				HandshakingState.debug = true;
				StateMachine.debug = true;
				TriggerConsumer.debug = true;
			}
			else
			{
				SSLSessionConfig.debug = false;
			}
			//TaskUtil.setThreadMultiplier(4);
			SSLContext sslContext = CryptoUtil.initSSLContext(null, null, IOUtil.locateFile(keystore), ksType, ksPassword.toCharArray(), null, null ,null);

			new NIOSocket(new InetSocketAddress(port), 256, new SSLNIOTunnelFactory(sslContext, remoteAddress), TaskUtil.getDefaultTaskProcessor());
		}
		catch(Exception e)
		{
			e.printStackTrace();
			TaskUtil.getDefaultTaskScheduler().close();
			TaskUtil.getDefaultTaskProcessor().close();
		}
	}


}