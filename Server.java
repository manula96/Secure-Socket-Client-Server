import javax.net.ssl.*;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.ByteArrayOutputStream;
import java.net.Socket;
import java.net.ServerSocket;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * The server, it will look for a client, receive a message and send one back.
 * It is current not secure, so to fix that, set up the SSL certificates and
 * add the following lines to the code in the correct places:
 * 
 * System.setProperty("javax.net.ssl.keyStore", "keystoreFile");
 * System.setProperty("javax.net.ssl.keyStorePassword", "password");
 * SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
 * SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(port);
 * SSLSocket socket = (SSLSocket) serverSocket.accept();
 * socket.setTcpNoDelay(true);
 * socket.startHandshake();
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
public class Server {
    public static void main(String[] args) {
        int port = 2250;  // Arbitrary non-privileged port
        System.out.format("Listening for a client on port %d\n", port);

        try {

            System.setProperty("javax.net.ssl.trustStore", "Certs/truststore.jks");
            System.setProperty("javax.net.ssl.trustStorePassword", "Seng6250");

            // Load the server certificate and private key from a PKCS12 file (Server.pfx)
            KeyStore serverKeyStore = KeyStore.getInstance("PKCS12");
            serverKeyStore.load(ClassLoader.getSystemResourceAsStream("Certs/Server.pfx"), "Seng6250".toCharArray());

            // Create a KeyManagerFactory to handle server authentication
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(serverKeyStore, "Seng6250".toCharArray());

            // Create an SSL context
            SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(keyManagerFactory.getKeyManagers(), null, new java.security.SecureRandom());

            // Create an SSL server socket factory
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

            // Create an SSL server socket
            SSLServerSocket serverSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(port);

            // Set the server to require client authentication (optional)
            serverSocket.setNeedClientAuth(true);

            // Accept incoming client connections
            SSLSocket socket = (SSLSocket) serverSocket.accept();;

            //------------- Client Authentication -------------------------
            SSLSession sslSession = socket.getSession();
            X509Certificate[] clientCertificates = (X509Certificate[]) sslSession.getPeerCertificates();
            // Verify the client's certificate (you can implement your custom logic here)
            // For example, checking the certificate chain and issuer

            for (Certificate certificate : clientCertificates) {
                // If it's an X.509 certificate, you can cast it for further inspection
                if (certificate instanceof X509Certificate) {
                    X509Certificate x509Certificate = (X509Certificate) certificate;

                    // Check the issuer's name to verify it's issued by the CA with the name "Barry"
                    String issuerName = x509Certificate.getIssuerX500Principal().getName();
                    if (!issuerName.contains("CN=BarryCA")) {
                        // Certificate is NOT trusted
                        socket.close();
                        System.out.println("\n*** CA not trusted ***");
                        System.out.println("Client might be an intruder...\n"+ "Server is shutting down...\n");
                        System.exit(0);
                    }
                    // Implement your certificate validation logic here
                    // Example: Verify the certificate chain, check issuer, expiration, etc.
                    // If validation fails, you can close the connection or take appropriate action
                }
            }

            //---------------

            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            System.out.format(
                    "Connected by %s:%d\n",
                    socket.getInetAddress().toString(),
                    socket.getPort()
            );

            // Receive a message from the client
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte data[] = new byte[1024];
            baos.write(data, 0, in.read(data));
            System.out.format("Client -> Server: %s\n", new String(data));

            // Send a message to the client
            out.write("I'll do the best I can. Let's get moving.".getBytes());

            // Close all streams
            in.close();
            out.close();
            socket.close();
            System.out.println("Server is shutting down...");

        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }
}