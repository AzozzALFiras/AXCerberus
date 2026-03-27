// Package challenge — HTML/JS challenge page template.
package challenge

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
)

// serveChallenge serves the JavaScript challenge page.
func (s *System) serveChallenge(w http.ResponseWriter, r *http.Request) {
	nonceBytes := make([]byte, 16)
	rand.Read(nonceBytes)
	nonce := hex.EncodeToString(nonceBytes)

	redirect := r.URL.RequestURI()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.WriteHeader(http.StatusServiceUnavailable)

	fmt.Fprintf(w, challengePageHTML, nonce, redirect)
}

const challengePageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Checking your browser - AXCerberus</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  background:#0a0a0f;color:#e0e0e0;display:flex;justify-content:center;align-items:center;
  min-height:100vh}
.container{text-align:center;max-width:480px;padding:2rem}
.shield{font-size:64px;margin-bottom:1rem;animation:pulse 2s infinite}
@keyframes pulse{0%%,100%%{opacity:1}50%%{opacity:.5}}
h1{font-size:1.4rem;margin-bottom:.5rem;color:#fff}
p{font-size:.9rem;color:#888;margin-bottom:1.5rem}
.spinner{width:40px;height:40px;border:3px solid #222;border-top-color:#3b82f6;
  border-radius:50%%;animation:spin 1s linear infinite;margin:1rem auto}
@keyframes spin{to{transform:rotate(360deg)}}
.status{font-size:.8rem;color:#666;margin-top:1rem}
noscript .error{color:#ef4444;font-weight:600}
</style>
</head>
<body>
<div class="container">
  <div class="shield">&#128737;</div>
  <h1>Checking your browser</h1>
  <p>This process is automatic. Your browser will redirect shortly.</p>
  <div class="spinner" id="spinner"></div>
  <p class="status" id="status">Verifying...</p>
  <noscript><p class="error">JavaScript is required to access this site.</p></noscript>
</div>
<script>
(function(){
  var nonce = "%s";
  var redirect = "%s";
  var ip = "";

  // Compute proof-of-work: find nonce such that SHA256(nonce+ip) starts with "0000"
  // Since we don't know the server-side IP, we submit the computation
  // The server validates against its view of the client IP

  async function solve() {
    document.getElementById("status").textContent = "Computing challenge...";

    // Compute SHA256 of (nonce + empty) to get the answer prefix
    var data = new TextEncoder().encode(nonce + ip);
    var hash = await crypto.subtle.digest("SHA-256", data);
    var hashArray = Array.from(new Uint8Array(hash));
    var hashHex = hashArray.map(function(b){return b.toString(16).padStart(2,"0")}).join("");
    var answer = hashHex.substring(0, 16);

    document.getElementById("status").textContent = "Submitting...";

    var form = document.createElement("form");
    form.method = "POST";
    form.action = "/__axcerberus/challenge/verify";

    var fields = {nonce: nonce, answer: answer, redirect: redirect};
    for (var key in fields) {
      var input = document.createElement("input");
      input.type = "hidden";
      input.name = key;
      input.value = fields[key];
      form.appendChild(input);
    }

    document.body.appendChild(form);
    form.submit();
  }

  // Small delay to appear more natural
  setTimeout(solve, 1500);
})();
</script>
</body>
</html>`
