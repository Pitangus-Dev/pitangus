<?php
$q = "SELECT * FROM users WHERE id = " . $_GET["id"];
// ruleid: appsec.php.sql-injection
mysqli_query($conn, $q);
// ruleid: appsec.php.command-injection
system("ping " . $_GET["host"]);
// ruleid: appsec.php.reflected-xss
echo $_GET["name"];
// ruleid: appsec.php.unserialize-from-request
$obj = unserialize($_COOKIE["data"]);
// ruleid: appsec.php.file-inclusion-from-request
include $_GET["page"];
// ruleid: appsec.php.eval-non-literal
eval($code);
// Safe counterparts: what the rules must leave alone.
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
// ok: appsec.php.sql-injection
$stmt->execute([$_GET["id"]]);
// ok: appsec.php.command-injection
system("ls -l " . escapeshellarg($_GET["dir"]));
// ok: appsec.php.eval-non-literal
eval("return 1;");
// ok: appsec.php.unserialize-from-request
$obj = json_decode($_COOKIE["data"], true);
// ok: appsec.php.file-inclusion-from-request
include __DIR__ . "/pages/home.php";
// ok: appsec.php.reflected-xss
echo htmlspecialchars($_GET["name"], ENT_QUOTES, "UTF-8");
