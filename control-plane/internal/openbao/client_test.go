package openbao

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Bidon15/popsigner/control-plane/internal/config"
)

// The secp256k1 plugin serves import at keys/<name>/import and reads the key
// material from "ciphertext"; anything else is a 403/404 from OpenBao.
func TestClient_ImportKey_UsesPluginImportContract(t *testing.T) {
	const pubKeyHex = "038318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75"

	var gotMethod, gotPath, gotToken string
	var gotBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotToken = r.Method, r.URL.Path, r.Header.Get("X-Vault-Token")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"name":"org_ns_key","public_key":"` + pubKeyHex +
			`","address":"cosmosaddr","exportable":false,"imported":true}}`))
	}))
	defer server.Close()

	client := NewClient(&config.OpenBaoConfig{Address: server.URL, Token: "test-token", Secp256k1Path: "signer"})

	pubKey, address, ethAddress, err := client.ImportKey("org_ns_key", "a2V5LW1hdGVyaWFs", false)
	if err != nil {
		t.Fatalf("ImportKey: %v", err)
	}

	if gotMethod != http.MethodPost || gotPath != "/v1/signer/keys/org_ns_key/import" {
		t.Errorf("request = %s %s, want POST /v1/signer/keys/org_ns_key/import", gotMethod, gotPath)
	}
	if gotToken != "test-token" {
		t.Errorf("X-Vault-Token = %q, want %q", gotToken, "test-token")
	}
	wantBody := map[string]interface{}{"ciphertext": "a2V5LW1hdGVyaWFs", "exportable": false}
	if len(gotBody) != len(wantBody) || gotBody["ciphertext"] != wantBody["ciphertext"] || gotBody["exportable"] != wantBody["exportable"] {
		t.Errorf("body = %v, want %v", gotBody, wantBody)
	}

	if got := strings.ToLower(ethAddress); got != "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266" {
		t.Errorf("ethAddress = %s, want 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", ethAddress)
	}
	if address != "cosmosaddr" || len(pubKey) != 33 {
		t.Errorf("address = %q, pubKey len = %d; want cosmosaddr, 33", address, len(pubKey))
	}
}
