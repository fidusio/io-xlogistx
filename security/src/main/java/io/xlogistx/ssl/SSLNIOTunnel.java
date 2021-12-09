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
package io.xlogistx.ssl;

import io.xlogistx.common.fsm.StateInt;
import io.xlogistx.common.fsm.Trigger;
import io.xlogistx.common.task.CallbackTask;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LoggerUtil;
import org.zoxweb.server.net.DefaultSKController;
import org.zoxweb.server.net.NIOChannelCleaner;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.net.ProtocolProcessor;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.task.TaskProcessor;
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


public class SSLNIOTunnel
    extends ProtocolProcessor
{
    private static final transient Logger log = Logger.getLogger(SSLNIOTunnel.class.getName());

	private static boolean debug = true;


	private static AtomicLong tunnelCounter = new AtomicLong();

	private SSLStateMachine sslStateMachine = null;
	private SSLSessionConfig config = null;




	final private InetSocketAddressDAO remoteAddress;
	final private SSLContext sslContext;

	private final long id = tunnelCounter.incrementAndGet();


	private void info(String str)
	{
		log.info("[" + id +"] " +str);
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
				config.beginHandshake();

				info("We have a connections <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
				if(config.inRemoteData == null)
				{
					//synchronized (config)
					{
						if(config.inRemoteData == null)
						{
              				config.inRemoteData = ByteBufferUtil.allocateByteBuffer(ByteBufferUtil.BufferType.DIRECT, ByteBufferUtil.DEFAULT_BUFFER_SIZE);
							config.remoteChannel = SocketChannel.open((new InetSocketAddress(remoteAddress.getInetAddress(), remoteAddress.getPort())));
							getSelectorController().register(null, config.remoteChannel, SelectionKey.OP_READ, this, new DefaultSKController(), false);
						}
					}
				}

			}



			info("AcceptNewData: " + key);
			if (key.channel() == config.sslChannel)
			{

				sslStateMachine.publish(new Trigger<CallbackTask<ByteBuffer>>(this, SSLEngineResult.HandshakeStatus.NEED_UNWRAP, null, new CallbackTask<ByteBuffer>() {
					@Override
					public void exception(Exception e) {
						// exception handling
						e.printStackTrace();
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
							finally{
								// enable channel reading
							}
						}
					}
				}));

				// to be removed
//				if(config.destinationBB == null)
//				{
//					config.destinationBB = ByteBufferUtil.allocateByteBuffer(ByteBufferUtil.DEFAULT_BUFFER_SIZE);
//					config.destinationChannel = SocketChannel.open((new InetSocketAddress(remoteAddress.getInetAddress(), remoteAddress.getPort())));
//
//					getSelectorController().register(null, config.destinationChannel, SelectionKey.OP_READ, this, config, false);
//				}


			}
			else if(key.channel() == config.remoteChannel)
			{
				sslStateMachine.publish(new Trigger<CallbackTask<ByteBuffer>>(this, SSLEngineResult.HandshakeStatus.NEED_WRAP, null, new CallbackTask<ByteBuffer>() {
					@Override
					public void exception(Exception e) {
						// exception handling
						e.printStackTrace();
					}

					@Override
					public void callback(ByteBuffer buffer) {
						// data handling
						if(buffer != null)
						{
							try {
								ByteBufferUtil.smartWrite(null, config.sslChannel, buffer);
							} catch (IOException e) {
								e.printStackTrace();
								// we should close
								close();
							}
						}
					}
				}));

			}

    		

    	}
    	catch(Exception e)
    	{
    		e.printStackTrace();


    		close();

    		info(System.currentTimeMillis() + ":Connection end " + key + ":" + key.isValid() + " " + availableThreads());
    		
    	}
		info( "End of SSLNIOTUNNEL-ACCEPT  available thread:" +availableThreads());
	}


	public  int availableThreads(){
		if(getExecutor() instanceof TaskProcessor)
			return ((TaskProcessor)getExecutor()).availableExecutorThreads();
		return -1;
	}

	protected void acceptConnection(NIOChannelCleaner ncc, AbstractSelectableChannel asc, boolean isBlocking) throws IOException {
		// must be modified do the handshake
		//((SocketChannel)asc).setOption(StandardSocketOptions.TCP_NODELAY, true);
    	sslStateMachine = SSLStateMachine.create(sslContext, null);
    	config = sslStateMachine.getConfig();
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
			int index = 0;
			int port = Integer.parseInt(args[index++]);
			InetSocketAddressDAO remoteAddress = new InetSocketAddressDAO(args[index++]);
			String keystore = args[index++];
			String ksType = args[index++];
			String ksPassword = args[index++];
			//TaskUtil.setThreadMultiplier(4);
			SSLContext sslContext = CryptoUtil.initSSLContext(IOUtil.locateFile(keystore), ksType, ksPassword.toCharArray(), null, null ,null);

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