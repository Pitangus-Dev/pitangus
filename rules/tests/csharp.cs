using System.Data.SqlClient; using System.Diagnostics; using System.Net; using System.Runtime.Serialization.Formatters.Binary;
class App {
  void Q(string name) {
    // ruleid: appsec.cs.sql-string-building
    var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + name + "'", conn);
    // ruleid: appsec.cs.process-start-concatenation
    Process.Start("cmd.exe", "/c ping " + name);
    // ruleid: appsec.cs.insecure-deserialization
    var bf = new BinaryFormatter();
    // ruleid: appsec.cs.certificate-validation-bypass
    ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;
    // ruleid: appsec.cs.weak-hash
    var h = MD5.Create();
  }
}
// ruleid: appsec.cs.razor-html-raw-non-literal
class View { string R(string x) { return Html.Raw(x).ToString(); } }
// Safe counterparts: what the rules must leave alone.
class Safe {
  void Q(string name, System.Net.Http.HttpClientHandler handler) {
    // ok: appsec.cs.sql-string-building
    var cmd = new SqlCommand("SELECT * FROM users WHERE name = @name", conn);
    // ok: appsec.cs.process-start-concatenation
    Process.Start("ls", "-l");
    // ok: appsec.cs.insecure-deserialization
    var data = System.Text.Json.JsonSerializer.Deserialize<Order>(name);
    // ok: appsec.cs.certificate-validation-bypass
    handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => e == System.Net.Security.SslPolicyErrors.None;
    // ok: appsec.cs.weak-hash
    var h = System.Security.Cryptography.SHA256.Create();
  }
  // ok: appsec.cs.razor-html-raw-non-literal
  string R() { return Html.Raw("<b>fixed</b>").ToString(); }
}
