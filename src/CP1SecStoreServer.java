import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;

public class CP1SecStoreServer {

	public static void main(String[] args) throws Exception{
		int port = 4321;	// socket address

		ServerSocket serverSocket;
		Socket clientSocket;
		serverSocket = new ServerSocket(port);

		String privateKeyFileName = "privateServer.der";
		String serverCertPath = "server.crt";

		Path keyPath = Paths.get(privateKeyFileName);
		byte[] privateKeyByteArray = Files.readAllBytes(keyPath);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByteArray);

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

		// Create encryption cipher
		Cipher rsaECipherPrivate = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		Cipher rsaDCipherPrivate = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		rsaECipherPrivate.init(Cipher.ENCRYPT_MODE, privateKey);
		rsaDCipherPrivate.init(Cipher.DECRYPT_MODE, privateKey);

		System.out.println("Accepting client connections now ...");
		clientSocket = serverSocket.accept();
		System.out.println("Client connection established!");

		BufferedReader in = new BufferedReader(
				new InputStreamReader(
						new DataInputStream(clientSocket.getInputStream())));
		PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

		boolean proceed = authenticationProtocol(in,out,rsaECipherPrivate,serverCertPath);

		if(!proceed){
			System.out.println("Authentication protocol failed!");
			serverSocket.close();
			return;
		}

		System.out.println("Waiting for encrypted file from client");
		Map<String,Long> fileUploadTimings = new HashMap<String, Long>();
		boolean clientDone = false;

		String csvFile = "CP1Timings.csv";
		FileWriter writer = new FileWriter(csvFile,true);
		CSVUtils.writeLine(writer, Arrays.asList("File Size", "Time Taken (ms)"));

		do{
			long startTime = System.currentTimeMillis();
			String clientsFileName = in.readLine();
			System.out.println("Received client's file name");
			int clientFileSize = Integer.parseInt(in.readLine());
			System.out.println("File size " + clientsFileName);
			byte[] encryptedDataFile = new byte[clientFileSize];

			// Read in encrypted file String representation

			String clientEncryptedFileString = in.readLine();
			System.out.println("Received client's encrypted file");
			encryptedDataFile = DatatypeConverter.parseBase64Binary(clientEncryptedFileString);

			byte[] clientDecryptedFileBytes = decryptFile(encryptedDataFile,rsaDCipherPrivate);
			FileOutputStream fileOutput = new FileOutputStream(clientsFileName);
			fileOutput.write(clientDecryptedFileBytes, 0, clientDecryptedFileBytes.length);
			fileOutput.close();
			System.out.println("Successfully saved client's file!");
			clientDone = ACs.CLIENTDONE.equals(in.readLine());
			System.out.println("Does client have more files to send? " + clientDone);
			long endTime = System.currentTimeMillis();
			long elapsedTime = endTime-startTime;
			fileUploadTimings.put(clientsFileName, elapsedTime);
			CSVUtils.writeLine(writer, Arrays.asList(clientsFileName, Long.toString(elapsedTime)));
		}while(!clientDone);

		writer.close();

		serverSocket.close();

		System.out.println(fileUploadTimings.toString());
	}

	private static boolean sendMsg(PrintWriter out,String msg){
		out.println(msg);
		out.flush();
		return true;
	}
	
	private static PublicKey getPublicKey(String key){
	    try{
	        byte[] byteKey = Base64.getDecoder().decode(key);
	        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
	        KeyFactory kf = KeyFactory.getInstance("RSA");

	        return kf.generatePublic(X509publicKey);
	    }
	    catch(Exception e){
	        e.printStackTrace();
	    }
	    return null;
	}
	
	private static boolean terminateConnection(PrintWriter out){
		out.println(ACs.TERMINATEMSG);
		return false;
	}

	private static boolean authenticationProtocol(BufferedReader in, PrintWriter out, Cipher rsaECipher, String serverCertPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{

		System.out.println("Starting authentication protocol");
		
		byte[] clientNonceInBytes = new byte[32];
		String clientNonce = in.readLine();
		clientNonceInBytes = DatatypeConverter.parseBase64Binary(clientNonce);	    
		
		byte[] encryptedNonce = rsaECipher.doFinal(clientNonceInBytes);
		out.println(DatatypeConverter.printBase64Binary(encryptedNonce));
		out.flush();
		
		if(!(in.readLine().equals(ACs.REQUESTSIGNEDCERT ))){
			System.out.println("Request Signed Certificate Error!");
			return terminateConnection(out);
		}
		
		File certFile = new File(serverCertPath);
		byte[] certBytes = new byte[(int) certFile.length()];
		BufferedInputStream certFileInput = new BufferedInputStream(new FileInputStream(certFile));
		certFileInput.read(certBytes,0,certBytes.length);
		certFileInput.close();
		
		// Prepping client to receive certificate in bytes
		System.out.println("Sending size of cert to client : " + certBytes.length);
		out.println(Integer.toString(certBytes.length) );	
		out.flush();
		// Sending signed cert of server - includes public key of client
		System.out.println("Sending certificate in string : ");
		out.println(DatatypeConverter.printBase64Binary(certBytes));
		out.flush();
		
		System.out.println("Waiting for client to confirm my identity");
		if(!ACs.SERVERIDENTIFIED.equals(in.readLine())){
			System.out.println("Client did not verify my ID properly");
			return terminateConnection(out);
		}
		
		// Generate nonce to ensure that client is a valid requester, and not a playback attacker
		byte[] serverNonce = new byte[32];
		Random randGen = SecureRandom.getInstanceStrong();
		randGen.nextBytes(serverNonce);
		String serverNonceString = new String(serverNonce, "UTF-16");
	
		 System.out.println("Sending nonce to client");
		 out.println(DatatypeConverter.printBase64Binary(serverNonce));
		 
		 byte[] encryptedServerNonce = new byte[128];
		 encryptedServerNonce = DatatypeConverter.parseBase64Binary(in.readLine());
		System.out.println("Received nonce encrypted with client's private key");
		
		System.out.println("Requesting for client public key");
		sendMsg(out,ACs.REQUESTCLIENTPUBLICKEY);
		
		String clientPublicKeyString = in.readLine();
		System.out.println("Received client's public key : " + clientPublicKeyString);
		
		Cipher rsaDCipherClientPublic = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		
		Key clientPublicKey = getPublicKey(clientPublicKeyString);
		rsaDCipherClientPublic.init(Cipher.DECRYPT_MODE, clientPublicKey);
		
		byte[] decryptedServerNonce = rsaDCipherClientPublic.doFinal(encryptedServerNonce);
		String decryptedNonceString = new String(decryptedServerNonce, "UTF-16");
		if(!decryptedNonceString.equals(serverNonceString)){
		   	 System.out.println("Client authentication failed!");
		   	 return terminateConnection(out);
		}
		
		System.out.println("Completed authentication protocol, server ready to receive files");
		sendMsg(out,ACs.SERVERREADYTORECEIVE);
		
		
		return true;
	}
	
	private static byte[] decryptFile(byte[] encryptedData, Cipher rsaDecryptionCipher) throws Exception{
		
		System.out.println("Decrypting client's files ... ");
		
		ByteArrayOutputStream byteOutput = new ByteArrayOutputStream();

	    int start = 0;
	    int fileSize = encryptedData.length;
	    while (start < fileSize) {
	        byte[] tempBuff;
	        if (fileSize - start >= 128) {
	            tempBuff = rsaDecryptionCipher.doFinal(encryptedData, start, 128);
	        } else {
	            tempBuff = rsaDecryptionCipher.doFinal(encryptedData, start, fileSize - start);
	        }
	        byteOutput.write(tempBuff, 0, tempBuff.length);
	        start += 128;
	    }
	    byte[] decryptedFileBytes = byteOutput.toByteArray();
	    byteOutput.close();
	    
	    System.out.println("Decryption complete");
	    return decryptedFileBytes;
	  }

	class OpenConnections implements Runnable{
		@Override
		public void run() {
		}
	}
}