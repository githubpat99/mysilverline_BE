$ErrorActionPreference = "Stop"

$session = "mysilverline"  # Name der gespeicherten WinSCP-Session
$local   = "C:\Users\patri\mysilverline.it-pin.ch\silverline-api\silverline-api.php"
$remote  = "/home/clients/cd018176a9efb9d6ecf8a0ae8be5e651/sites/mysilverline.it-pin.ch/wp-content/plugins/silverline-api/silverline-api.php"

# Optional: nicht deployen, wenn uncommitted changes
if ((git status --porcelain).Length -gt 0) {
  throw "Uncommitted changes in plugin repo. Commit first."
}

& "C:\Program Files (x86)\WinSCP\WinSCP.com" `
  "/command" `
  "open storedsession:$session" `
  "put `"$local`" `"$remote`"" `
  "exit"
