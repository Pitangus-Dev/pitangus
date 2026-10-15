package main
import ("crypto/tls"; "database/sql"; "fmt"; "net/http"; "os"; "os/exec"; "html/template")
func h(w http.ResponseWriter, r *http.Request, db *sql.DB) {
  name := r.URL.Query().Get("name")
  // ruleid: appsec.go.sql-string-building
  db.Query("SELECT * FROM users WHERE name = '" + name + "'")
  // ruleid: appsec.go.sql-string-building
  db.Exec(fmt.Sprintf("DELETE FROM t WHERE id = %s", name))
  // ruleid: appsec.go.shell-command-non-literal
  exec.Command("sh", "-c", name)
  // ruleid: appsec.go.path-traversal-from-request
  f, _ := os.Open("/data/" + name); _ = f
  // ruleid: appsec.go.template-html-unescaped
  _ = template.HTML(name)
  // ruleid: appsec.go.tls-insecure-skip-verify
  _ = &tls.Config{InsecureSkipVerify: true}
}
import "crypto/md5"
// ruleid: appsec.go.weak-hash
func weak() { _ = md5.New() }

// A framework's request context is user input; database rows aren't.
func download(c *gin.Context) {
  // ruleid: appsec.go.path-traversal-from-request
  f, _ := os.Open("/data/" + c.Query("file")); _ = f
}
func export(db *sql.DB) {
  rows, _ := db.Query("SELECT name FROM files")
  // ok: appsec.go.path-traversal-from-request
  f, _ := os.Open(fmt.Sprint(rows)); _ = f
}

// Safe counterparts: what the rules must leave alone.
func safe(db *sql.DB, name string, data []byte) {
  // ok: appsec.go.sql-string-building
  db.Query("SELECT * FROM users WHERE name = $1", name)
  // ok: appsec.go.shell-command-non-literal
  exec.Command("ls", "-l", name)
  // ok: appsec.go.template-html-unescaped
  _ = template.HTML("<b>fixed</b>")
  // ok: appsec.go.tls-insecure-skip-verify
  _ = &tls.Config{MinVersion: tls.VersionTLS12}
}
import "crypto/sha256"
// ok: appsec.go.weak-hash
func strong() { _ = sha256.New() }
