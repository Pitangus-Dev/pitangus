import java.sql.*; import java.io.*; import javax.net.ssl.*; import java.security.cert.X509Certificate;
public class App {
  void q(Connection con, String name) throws Exception {
    Statement st = con.createStatement();
    // ruleid: appsec.java.sql-concatenation
    st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    // ruleid: appsec.java.runtime-exec-concatenation
    Runtime.getRuntime().exec("ping " + name);
    // ruleid: appsec.java.hardcoded-password
    String password = "hunter2-hardcoded";
  }
  // ruleid: appsec.java.objectinputstream-readobject
  Object read(ObjectInputStream in) throws Exception { return in.readObject(); }
  TrustManager tm = new X509TrustManager() {
    // ruleid: appsec.java.trust-all-certificates
    public void checkServerTrusted(X509Certificate[] c, String a) { }
    // ruleid: appsec.java.trust-all-certificates
    public void checkClientTrusted(X509Certificate[] c, String a) { }
    public X509Certificate[] getAcceptedIssuers() { return null; }
  };
}
class More {
  void x(javax.crypto.Cipher c, javax.xml.parsers.DocumentBuilderFactory f, org.springframework.security.config.annotation.web.builders.HttpSecurity http) throws Exception {
    // ruleid: appsec.java.weak-cipher
    javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("DES/ECB/PKCS5Padding");
    // ruleid: appsec.java.xxe-documentbuilder
    javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
    // ruleid: appsec.java.spring-csrf-disabled
    http.csrf().disable();
  }
  // ruleid: appsec.java.hostname-verifier-allow-all
  HostnameVerifier hv = new HostnameVerifier() { public boolean verify(String h, SSLSession s) { return true; } };
}
// Safe counterparts: what the rules must leave alone.
class Safe {
  void x(Connection con, String name, javax.xml.parsers.DocumentBuilderFactory unused, org.springframework.security.config.annotation.web.builders.HttpSecurity http) throws Exception {
    // ok: appsec.java.sql-concatenation
    PreparedStatement ps = con.prepareStatement("SELECT * FROM users WHERE name = ?");
    // ok: appsec.java.runtime-exec-concatenation
    new ProcessBuilder("ls", "-l", name).start();
    // ok: appsec.java.weak-cipher
    javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
    // ok: appsec.java.xxe-documentbuilder
    javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    // ok: appsec.java.spring-csrf-disabled
    http.csrf(csrf -> csrf.ignoringRequestMatchers("/webhooks/**"));
    // ok: appsec.java.hardcoded-password
    String password = System.getenv("DB_PASSWORD");
    // ruleid: appsec.java.hardcoded-password
    String JWT_PASSWORD = "bm5n3SkxCX4kKRy4";
    // ruleid: appsec.java.hardcoded-password
    String LEAKED_API_KEY = "INTERNAL-API-KEY-987";
    // ok: appsec.java.hardcoded-password
    String PASSWORD_SALT_ADMIN = "DeliberatelyInsecure1235";
    // ok: appsec.java.hardcoded-password
    String RESET_PASSWORD_PATH = "/challenge/reset-password";
    // ok: appsec.java.hardcoded-password
    String RESET_PASSWORD = CHALLENGE_PATH + "/reset-password";
    // ok: appsec.java.hardcoded-password
    String PASSWORD_PARAM = "password_confirmation";
    // ok: appsec.java.hardcoded-password
    String TOKEN_HEADER = "Authorization";
    // ok: appsec.java.hardcoded-password
    String secretKey = "spring.datasource.password";
    // ok: appsec.java.hardcoded-password
    String PASSWORD_REGEX = "^(?=.*[A-Z]).{8,}$";
    // ok: appsec.java.hardcoded-password
    String passwordError = "The password is too short";
    // ok: appsec.java.hardcoded-password
    String tokenUrl = "https://auth.example.com/oauth/token";
    // ok: appsec.java.hardcoded-password
    String secret = "${JWT_SECRET}";
  }
  // ok: appsec.java.objectinputstream-readobject
  Object read(java.io.DataInputStream in) throws Exception { return in.readUTF(); }
  // ok: appsec.java.trust-all-certificates
  public void checkServerTrusted(X509Certificate[] chain, String auth) throws java.security.cert.CertificateException { delegate.checkServerTrusted(chain, auth); }
  // ok: appsec.java.hostname-verifier-allow-all
  public boolean verify(String host, SSLSession session) { return HttpsURLConnection.getDefaultHostnameVerifier().verify(host, session); }
}
