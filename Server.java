import javax.net.ssl.*;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.ByteArrayOutputStream;
import java.net.Socket;
import java.net.ServerSocket;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class Server {
    public static void main(String[] args) {
        int port = 2250;  // Arbitrary non-privileged port
        System.out.format("Listening for a client on port %d\n", port);

        try {

            System.setProperty("javax.net.ssl.trustStore", "Certs/truststore.jks");
            System.setProperty("javax.net.ssl.trustStorePassword", Variables.Password);

            // Load the server certificate and private key from a PKCS12 file (Server.pfx)
            KeyStore serverKeyStore = KeyStore.getInstance("PKCS12");
            serverKeyStore.load(ClassLoader.getSystemResourceAsStream("Certs/Server.pfx"), Variables.Password.toCharArray());

            // Create a KeyManagerFactory to handle server authentication
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(serverKeyStore, Variables.Password.toCharArray());

            // Create an SSL context
            SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(keyManagerFactory.getKeyManagers(), null, new java.security.SecureRandom());

            // Create an SSL server socket factory
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

            // Create an SSL server socket
            SSLServerSocket serverSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(port);

            // Set the server to require client authentication
            serverSocket.setNeedClientAuth(true);

            // Accept incoming client connections
            SSLSocket socket = (SSLSocket) serverSocket.accept();;

            //------------- Client Authentication -------------------------
            SSLSession sslSession = socket.getSession();
            X509Certificate[] clientCertificates = (X509Certificate[]) sslSession.getPeerCertificates();
            for (Certificate certificate : clientCertificates) {
                // If it's an X.509 certificate, you can cast it for further inspection
                if (certificate instanceof X509Certificate) {
                    X509Certificate x509Certificate = (X509Certificate) certificate;

                    // Check the issuer's name to verify it's issued by the CA with the name "Barry"
                    String issuerName = x509Certificate.getIssuerX500Principal().getName();
                    if (!issuerName.contains("CN=BarryCA ")) {
                        // Certificate is NOT trusted
                        socket.close();
                        System.out.println("\n*** CA not trusted ***");
                        System.out.println("Client might be an intruder...\n"+ "Server is shutting down...\n");
                        System.exit(0);
                    }
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