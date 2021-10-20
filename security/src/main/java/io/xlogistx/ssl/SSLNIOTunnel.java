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

import io.xlogistx.common.fsm.Trigger;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LoggerUtil;
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
import java.nio.channels.Channel;
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
	private SSLConfig config = null;




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
		return "SSLNIO Tunnel";
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
			if(config.sslChannel == null)
			{

				info("We have a connections <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
				sslStateMachine.publish(new Trigger<Channel>(this, null, key.channel(), SSLStateMachine.SessionState.WAIT_FOR_HANDSHAKING));
				return;
			}


			int read = 0;
			info("AcceptNewData: " + key);
			if (key.channel() == config.sslChannel)
			{
				SSLEngineResult.HandshakeStatus status = config.getHandshakeStatus();
				//if(sslSessionSM.getCurrentState().getName().equals(SSLStateMachine.SessionState.HANDSHAKING.getName()))
				if(config.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING)
				{
					info("We are still HAND_SHAKING_BABY:" + config.getHandshakeStatus());

					//config.sslChannelReadState = false;
					sslStateMachine.publish(new Trigger<SSLConfig>(this, null, config, status));
					info("CURRENT STATE: " + config.getHandshakeStatus());
//					if(config.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING){
//						sslStateMachine.publish(new Trigger<SSLConfig>(this, null, config, status));
//					}

					return;

				}
				if(config.destinationBB == null)
				{
					config.destinationBB = ByteBufferUtil.allocateByteBuffer(ByteBufferUtil.DEFAULT_BUFFER_SIZE);
					config.destinationChannel = SocketChannel.open((new InetSocketAddress(remoteAddress.getInetAddress(), remoteAddress.getPort())));

					getSelectorController().register(null, config.destinationChannel, SelectionKey.OP_READ, this, false);
				}

				// we need to unwrap
				read = config.sslChannel.read(config.inNetData);
				info("Reading SSL data: " + read + " " + config.inNetData);
				if(read > 0)
				{

					SSLEngineResult result = null;

					result = config.smartUnwrap(config.inNetData, config.inAppData);

					 info( "UNWRAPING-SSL-DATA:" + result +" " + config.inNetData);

					  if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
						switch (result.getStatus()) {
						  case BUFFER_UNDERFLOW:
						  case BUFFER_OVERFLOW:
							info("READ-SSL-UNWRAP_PROBLEM: " + result);
							break;
						  case OK:
							ByteBufferUtil.smartWrite(config.destinationChannel, config.inAppData);
							break;
						  case CLOSED:
							info(" BEFORE-READ-CLOSED: " + result);
							if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP) {

							  result = config.smartWrap(ByteBufferUtil.EMPTY, config.outNetData);
							  info(
								  " READ-CLOSED-NEED_WRAP: "
									  + result
									  + " outNetData: "
									  + config.outNetData.position());
							  ByteBufferUtil.smartWrite(config.sslChannel, config.outNetData);
							}
							close();
							info(" CLOSED_PROBLEM: " + result);
							break;
						}
					  }
					  else
					  {
					  	 info("UNWRAP-MUST-HANDSHAKE-AGAIN: " + result);
					  	 sslStateMachine.publish(new Trigger<SSLConfig>(this, null, config, status));
					  }
				}
			}
			else if(key.channel() == config.destinationChannel)
			{

				read = config.destinationChannel.read(config.destinationBB);
				if(read > 0)
				{

					info("BEFORE-WRAPPING-READ-DATA:" + config.outNetData);

					SSLEngineResult result = null;

					result = config.smartWrap(config.destinationBB, config.outNetData);

					info("READ-WRAPPING-DATA:" + result);
					  if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
						switch (result.getStatus()) {
						  case BUFFER_UNDERFLOW:
						  case BUFFER_OVERFLOW:
							info("WRAP_PROBLEM: " + result);
							break;
						  case OK:
							int bytesWritten = ByteBufferUtil.smartWrite(config.sslChannel, config.outNetData);
							info("Byteswritten to ssl channel " + bytesWritten );

							break;
						  case CLOSED:
							info("CLOSED-WRAP_PROBLEM: " + result);
							if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP) {

							  result = config.smartWrap(ByteBufferUtil.EMPTY, config.outNetData);
							  info(
								  " READ-CLOSED-NEED_WRAP: "
									  + result
									  + " outNetData: "
									  + config.outNetData.position());
							  ByteBufferUtil.smartWrite(config.sslChannel, config.outNetData);
							}
							close();
							break;
						}

					}
					else {
						  info("WRAP-MUST-HANDSHAKE-AGAIN:" + result);
					  }
				}
			}

    		
    		if (read == -1)
    		{
    			if (debug) info("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+Read:" + read);
    			
    			//getSelectorController().cancelSelectionKey(key);

    			close();
    				
    			if (debug) info(key + ":" + key.isValid()+ " " );
    		}
    	}
    	catch(Exception e)
    	{
    		e.printStackTrace();


    		close();

    		if (debug) info(System.currentTimeMillis() + ":Connection end " + key + ":" + key.isValid() + " " + TaskUtil.getDefaultTaskProcessor().availableExecutorThreads());
    		
    	}
		info( "End of SSLNIOTUNNEL-ACCEPT");
	}


	protected void acceptConnection(NIOChannelCleaner ncc, AbstractSelectableChannel asc, boolean isBlocking) throws IOException {
		// must be modified do the handshake
		//((SocketChannel)asc).setOption(StandardSocketOptions.TCP_NODELAY, true);
    	sslStateMachine = SSLStateMachine.create(sslContext, null);
    	config = sslStateMachine.getConfig();
    	config.selectorController = getSelectorController();



    	sslStateMachine.start();


		getSelectorController().register(ncc,  asc, SelectionKey.OP_READ, this, isBlocking);
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