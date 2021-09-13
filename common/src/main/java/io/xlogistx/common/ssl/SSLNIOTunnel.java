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
package io.xlogistx.common.ssl;

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
import java.util.logging.Logger;


public class SSLNIOTunnel
    extends ProtocolProcessor
{
    private static final transient Logger log = Logger.getLogger(SSLNIOTunnel.class.getName());

	private static boolean debug = true;




//	private SocketChannel destinationChannel = null;
//
//	private ByteBuffer destinationBB = null;

	private SSLSessionSM sslSessionSM = null;
	private SSLSessionConfig config = null;




	final private InetSocketAddressDAO remoteAddress;
	final private SSLContext sslContext;

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
		if(sslSessionSM != null)
			config.close();

		log.info("closed:" + remoteAddress);
	}




	@Override
	public  void accept(SelectionKey key)
	{
		log.info("Start of Accept SSLNIOTUNNEL");
		try
    	{
			// first call
			if(config.sslChannel == null)
			{

				log.info("We have a connections <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
				sslSessionSM.publish(new Trigger<Channel>(this, null, key.channel(), SSLSessionSM.SessionState.WAIT_FOR_HANDSHAKING));
				return;
			}


			int read = 0;
			log.info("AcceptNewData: " + key);
			if (key.channel() == config.sslChannel)
			{

				if(config.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING)
				{
					log.info("We are still HAND_SHAKING_BABY");

					//config.sslChannelReadState = false;
					sslSessionSM.publish(new Trigger<Channel>(this, null, key.channel(), SSLSessionSM.SessionState.HANDSHAKING));
					log.info("CURRENT STATE: " + sslSessionSM.getCurrentState());
					return;
				}
				if(config.destinationBB == null)
				{
					config.destinationBB = ByteBufferUtil.allocateByteBuffer(ByteBufferUtil.DEFAULT_BUFFER_SIZE);
					config.destinationChannel = SocketChannel.open((new InetSocketAddress(remoteAddress.getInetAddress(), remoteAddress.getPort())));

					getSelectorController().register(null, config.destinationChannel, SelectionKey.OP_READ, this, false);
				}

				// we need to unwrap
//				config.inNetData.clear();
//				config.inAppData.clear();
				read = config.sslChannel.read(config.inNetData);
				log.info("Reading SSL data: " + read + " " + config.inNetData);
				if(read > 0)
				{
					config.inNetData.flip();
					SSLEngineResult result = null;
					while (config.inNetData.hasRemaining()) {
					  result = config.unwrap(config.inNetData, config.inAppData);
					  log.info( "UNWRAPING-SSL-DATA:" + result +" " + config.inNetData);
//					  if(result.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING)
//					  {
//
//					  }
					}
					config.inNetData.compact();

					switch (result.getStatus())
					{
					  case BUFFER_UNDERFLOW:
					  case BUFFER_OVERFLOW:
						log.info("READ-SSL-UNWRAP_PROBLEM: " + result);
						break;
					  case OK:
						ByteBufferUtil.write(config.destinationChannel, config.inAppData);
						config.inAppData.compact();
						break;
					  case CLOSED:
						  log.info( " BEFORE-READ-CLOSED: " + result);
						if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
						  // peerAppData.flip();
						  config.outNetData.clear();
						  result = config.wrap(ByteBufferUtil.EMPTY, config.outNetData);
						  log.info( " READ-CLOSED-NEED_WRAP: " + result + " outNetData: " + config.outNetData.position());
						  ByteBufferUtil.write(config.sslChannel, config.outNetData);
						}
						close();
						log.info( " CLOSED_PROBLEM: " + result);
						break;
					}
				}
			}
			else if(key.channel() == config.destinationChannel)
			{
				config.destinationBB.clear();
				read = config.destinationChannel.read(config.destinationBB);
				if(read > 0)
				{

					log.info("BEFORE-WRAPPING-READ-DATA:" + config.outNetData);

					SSLEngineResult result = null;
					config.destinationBB.flip();
					result = config.wrap(config.destinationBB, config.outNetData);
					log.info("READ-WRAPPING-DATA:" + result);

					switch (result.getStatus()) {
					  case BUFFER_UNDERFLOW:
					  case BUFFER_OVERFLOW:
						log.info("WRAP_PROBLEM: " + result);
						break;
					  case OK:
						ByteBufferUtil.write(config.sslChannel, config.outNetData);
						config.outNetData.compact();

						break;
					  case CLOSED:
						log.info("CLOSED-WRAP_PROBLEM: " + result);
						close();
						break;
					}

				}
			}


//			if(key.channel() == sslsc.sslChannel)
//			{
//				// reading encrypted data
//				if (debug) log.info("incoming data on secure channel " + key);
//				ByteBuffer temp = niosslServer.read((SocketChannel) key.channel(), sslsc.sslEngine, sslsc.appData);
//				if(temp == null) {
//					close();
//					return;
//				}
//
//
//				ByteBufferUtil.write(destinationChannel, temp);
//
//				log.info("decrypted buffer : " + temp);
//			}
//			else if (key.channel() == destinationChannel)
//			{
//				if (debug) log.info("incoming data from remote channel " + key);
//
//				do
//				{
//
//					destinationBB.clear();
//
//					// modify if currentSourceChannel == sourceChannel
//					read = ((SocketChannel) key.channel()).read(destinationBB);
//					if (debug) log.info("byte read: " + read);
//					if (read > 0)
//					{
//						// modify currentDestinationChannel == sourceChannel
//						niosslServer.write((SocketChannel) sslsc.sslChannel, sslsc.sslEngine, destinationBB);
//					}
//				}
//				while(read > 0);
//			}




    		
    		if (read == -1)
    		{
    			if (debug) log.info("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+Read:" + read);
    			
    			//getSelectorController().cancelSelectionKey(key);

    			close();
    				
    			if (debug) log.info(key + ":" + key.isValid()+ " " );
    		}
    	}
    	catch(Exception e)
    	{
    		e.printStackTrace();


    		close();

    		if (debug) log.info(System.currentTimeMillis() + ":Connection end " + key + ":" + key.isValid() + " " + TaskUtil.getDefaultTaskProcessor().availableExecutorThreads());
    		
    	}
		log.info( "End of SSLNIOTUNNEL-ACCEPT");
	}


	protected void acceptConnection(NIOChannelCleaner ncc, AbstractSelectableChannel asc, boolean isBlocking) throws IOException {
		// must be modified do the handshake

    	sslSessionSM = SSLSessionSM.create(sslContext, null);
    	config = sslSessionSM.getConfig();
    	config.selectorController = getSelectorController();



    	sslSessionSM.start();


		getSelectorController().register(ncc,  asc, SelectionKey.OP_READ, this, isBlocking);
	}





	@SuppressWarnings("resource")
    public static void main(String... args)
    {
    LoggerUtil.enableDefaultLogger("io.xlogistx");
		try
		{
			int index = 0;
			int port = Integer.parseInt(args[index++]);
			InetSocketAddressDAO remoteAddress = new InetSocketAddressDAO(args[index++]);
			String keystore = args[index++];
			String ksType = args[index++];
			String ksPassword = args[index++];
			TaskUtil.setThreadMultiplier(4);
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