import javax.net.ssl.*;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.ByteArrayOutputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

/**
 * The client, it will connect to the server, send a message and receive one back.
 * It is currently not secure, so to fix that, set up the SSL certificates and
 * add the following lines to the code where appropriate:
 * 
 * System.setProperty("javax.net.ssl.keyStore", "keystoreFile");
 * System.setProperty("javax.net.ssl.keyStorePassword", "password");
 * SSLContext sc = SSLContext.getInstance("SSL");
 * sc.init(null, trustAllCerts, new java.security.SecureRandom());
 * SSLSocketFactory factory = (SSLSocketFactory) sc.getSocketFactory();
 * SSLSocket s = (SSLSocket) factory.createSocket(hostname, port);
 * s.setTcpNoDelay(true);
 * s.startHandshake();
 * 
 * For further information refer to https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/net/ssl/SSLSocket.html
 * 
 * In addition to the additional code, you will need to add the certificates to a keystore file via the 
 * keytool command, you will need the following commands:
 * 
 * keytool -keystore keystore -genkeypair -keyalg rsa
 * keytool -importkeystore -srckeystore keystore -destkeystore keystore.p12 -deststoretype PKCS12
 * keytool -import -trustcacerts -keystore test -file Certificate.crt -alias cert1
 * 
 * The first command creates a private and public key, the second exports the private key to be used by XCA,
 * and the third is used after creating the certificates using XCA and imports them into the keystore. The
 * third command must be run for each certificate created and exported from XCA, each time with a different
 * alias.
 */

public class Client {
    public static void main(String[] args) {
        String hostname = "localhost";  // Server hostname or IP
        int port = 2250; // The same port as used by the server
        System.out.format("Connecting to the server at %s:%d\n", hostname, port);

        try {

            System.setProperty("javax.net.ssl.trustStore", "Certs/truststore.jks");
            System.setProperty("javax.net.ssl.trustStorePassword", "Seng6250");

            //System.setProperty("javax.net.debug", "ssl");
            // Load your client certificate and private key from a PKCS12 file (client.pfx)
            KeyStore clientKeyStore = KeyStore.getInstance("PKCS12");
            clientKeyStore.load(ClassLoader.getSystemResourceAsStream("Certs/Client.pfx"), "Seng6250".toCharArray());

            // Initialize the KeyManagerFactory with the client's key store
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(clientKeyStore, "Seng6250".toCharArray());

            // Create an SSL context with a custom TrustManager
            SSLContext sslContext = SSLContext.getInstance("SSL");

            // Load the CA certificate
            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            char[] trustStorePassword = "Seng6250".toCharArray();
            trustStore.load(ClassLoader.getSystemResourceAsStream("Certs/Barry.p12"), trustStorePassword);
            //trustStore.load(ClassLoader.getSystemResourceAsStream("Certs/truststore.jks"), trustStorePassword);


            // Create a TrustManagerFactory for the CA trust store
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);


            // Initialize the SSL context with the client's key and trust managers
            sslContext.init(
                    keyManagerFactory.getKeyManagers(),
                    trustManagerFactory.getTrustManagers(),
                    null
            );

            // Create an SSL socket factory
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            // Create an SSL socket
            SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket(hostname, port);

            // Authenticate with the server using the client certificate and private key
            socket.startHandshake();

/*            // Check the handshake status
            SSLSession session = socket.getSession();
            if (!session.isValid()) {
                // Handle the handshake failure gracefully
                System.err.println("Handshake failed. Server did not trust the connection");
                // Exit the program without errors
                System.exit(0);
            }*/

            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream());

            // Send a message to the server
            out.write("Be careful. There's no telling what tricks they have planned.".getBytes());
        
            // Receive a message from the server
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte data[] = new byte[1024];
            baos.write(data, 0, in.read(data));
            System.out.format("Client <- Server: %s\n", new String(data));

            // Close all streams
            in.close();
            out.close();
            socket.close();
        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
            System.err.println("\n *** Handshake failed. Server did not trust the connection ***\n");
            // Exit the program without errors
            System.exit(0);
        }
    }
}