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
import java.nio.channels.ByteChannel;
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




	private SocketChannel destinationChannel = null;

	private ByteBuffer destinationBB = null;

	private SSLSessionSM sslSessionSM = null;




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
			//sslSessionSM.publish(new Trigger(this, null, null, SSLSessionSM.SessionState.CLOSE));
			sslSessionSM.getConfig().close();

		log.info("closed:" + remoteAddress);
	}




	@Override
	public  void accept(SelectionKey key)
	{
		log.info("Start of Accept SSLNIOTUNNEL");
		try
    	{
			// first call
			if(sslSessionSM.getConfig().sslChannel == null)
			{
				//sslSessionSM.getConfig().sslChannelReadState = false;

				log.info("We have a connections <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
				sslSessionSM.publish(new Trigger<Channel>(this, null, key.channel(), SSLSessionSM.SessionState.WAIT_FOR_HANDSHAKING));
				return;
			}


			int read = 0;
			log.info("AcceptNewData: " + key);
			if (key.channel() == sslSessionSM.getConfig().sslChannel)
			{

				if(sslSessionSM.getCurrentState().getName().equals(SSLSessionSM.SessionState.HANDSHAKING.getName()))
				{
					log.info("We are still HAND_SHAKING_BABY");
					//sslSessionSM.getConfig().sslChannelReadState = false;
					sslSessionSM.publish(new Trigger<Channel>(this, null, key.channel(), SSLSessionSM.SessionState.HANDSHAKING));
					log.info("CURRENT STATE: " + sslSessionSM.getCurrentState());
					return;
				}
				if(destinationBB == null)
				{
					destinationBB = ByteBufferUtil.allocateByteBuffer(ByteBufferUtil.DEFAULT_BUFFER_SIZE);
					destinationChannel = SocketChannel.open((new InetSocketAddress(remoteAddress.getInetAddress(), remoteAddress.getPort())));
					sslSessionSM.getConfig().otherCloseable = destinationChannel;
					getSelectorController().register(NIOChannelCleaner.DEFAULT, destinationChannel, SelectionKey.OP_READ, this, false);
				}
				SSLSessionConfig config = sslSessionSM.getConfig();
				// we need to unwrap
				config.inNetData.clear();
				config.inAppData.clear();
				read = ((SocketChannel)config.sslChannel).read(config.inNetData);
				log.info("Reading SSL data: " + read + " " + config.inNetData);
				if(read > 0){
					config.inNetData.flip();
					SSLEngineResult result = null;
					//synchronized (config.sslEngine){
					result = config.sslEngine.unwrap(config.inNetData, config.inAppData);
					//}

					switch (result.getStatus())
					{

						case BUFFER_UNDERFLOW:
						case BUFFER_OVERFLOW:
							log.info("UNWRAP_PROBLEM: " + result);
							break;
						case OK:
							ByteBufferUtil.write(destinationChannel, config.inAppData);
							break;
						case CLOSED:
							if(result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP)
							{
								//peerAppData.flip();
								config.outNetData.clear();
								result = config.sslEngine.wrap(ByteBufferUtil.DUMMY, config.outNetData);
								log.info(Thread.currentThread() + " READ-CLOSED-NEED_WRAP: " + result);
								ByteBufferUtil.write((SocketChannel)config.sslChannel, config.outNetData);
							}
							close();
							log.info("UNWRAP_PROBLEM: " + result);
							break;
					}
				}

			}
			else if(key.channel() == destinationChannel)
			{
				destinationBB.clear();
				read = destinationChannel.read(destinationBB);
				if(read > 0)
				{
					SSLSessionConfig config =  sslSessionSM.getConfig();
					config.outNetData.clear();
					destinationBB.flip();
					SSLEngineResult result = null;
				    //synchronized (config.sslEngine) {
						result = config.sslEngine.wrap(destinationBB, config.outNetData);
					//}



					switch (result.getStatus())
					{

						case BUFFER_UNDERFLOW:
						case BUFFER_OVERFLOW:
							log.info("WRAP_PROBLEM: " + result);
							break;
						case OK:
							ByteBufferUtil.write((ByteChannel) config.sslChannel, config.outNetData);
							break;
						case CLOSED:
							log.info("WRAP_PROBLEM: " + result);
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
    				
    			if (debug) log.info(key + ":" + key.isValid()+ " " + Thread.currentThread());
    		}
    	}
    	catch(Exception e)
    	{
    		if (debug) e.printStackTrace();
    		close();

    		if (debug) log.info(System.currentTimeMillis() + ":Connection end " + key + ":" + key.isValid()+ " " + Thread.currentThread() + " " + TaskUtil.getDefaultTaskProcessor().availableExecutorThreads());
    		
    	}
	}


	protected void acceptConnection(NIOChannelCleaner ncc, AbstractSelectableChannel asc, boolean isBlocking) throws IOException {
		// must be modified do the handshake

    	sslSessionSM = SSLSessionSM.create(sslContext, null);
    	sslSessionSM.getConfig().selectorController = getSelectorController();
    	sslSessionSM.getConfig().sslEngine = sslSessionSM.getConfig().sslContext.createSSLEngine();


    	sslSessionSM.start();


		getSelectorController().register(ncc,  asc, SelectionKey.OP_READ, this, isBlocking);
	}



//	@Override
//	public boolean channelReadState(Channel channel)
//	{
//		if(channel == destinationChannel)
//			return true;
//
//		if(channel == sslSessionSM.getConfig().sslChannel)
//		{
//			return sslSessionSM.getConfig().sslChannelReadState;
//		}
//
//		return false;
//	}

	@SuppressWarnings("resource")
    public static void main(String... args)
    {
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