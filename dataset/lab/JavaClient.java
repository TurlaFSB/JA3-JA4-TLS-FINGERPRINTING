// JavaClient.java: minimal JDK HttpClient HTTPS client for the dataset lab.
// Usage: java JavaClient.java URL COUNT [urlconn]   (urlconn uses HttpsURLConnection; certificate checks are disabled on
// purpose: the lab server uses a throwaway self-signed certificate)
import java.net.URI;
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class JavaClient {
    public static void main(String[] args) throws Exception {
        TrustManager[] trustAll = {new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String t) {}
            public void checkServerTrusted(X509Certificate[] c, String t) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }};
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, trustAll, null);
        SSLParameters params = new SSLParameters();
        params.setEndpointIdentificationAlgorithm("");
        int n = Integer.parseInt(args[1]);
        boolean urlconn = args.length > 2 && args[2].equals("urlconn");
        for (int i = 0; i < n; i++) {
            if (urlconn) {
                try {
                    HttpsURLConnection c = (HttpsURLConnection) new URL(args[0]).openConnection();
                    c.setSSLSocketFactory(ctx.getSocketFactory());
                    c.setHostnameVerifier((h, sess) -> true);
                    c.getInputStream().readAllBytes();
                    c.disconnect();
                } catch (Exception e) {
                    System.err.println(e);
                }
                continue;
            }
            HttpClient client = HttpClient.newBuilder().sslContext(ctx).sslParameters(params).build();
            try {
                client.send(HttpRequest.newBuilder(URI.create(args[0])).build(),
                        HttpResponse.BodyHandlers.discarding());
            } catch (Exception e) {
                System.err.println(e);
            }
        }
    }
}
