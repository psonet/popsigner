package config

import (
	"os"
	"testing"
)

func TestCookieDomainDefault(t *testing.T) {
	d := t.TempDir()
	old, _ := os.Getwd()
	defer os.Chdir(old)
	os.Chdir(d)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Auth.CookieDomain != ".popsigner.com" {
		t.Fatalf("default = %q", cfg.Auth.CookieDomain)
	}
}

func TestCookieDomainEmptyOverride(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(d+"/config.yaml", []byte("auth:\n  cookie_domain: \"\"\n"), 0o644)
	old, _ := os.Getwd()
	defer os.Chdir(old)
	os.Chdir(d)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Auth.CookieDomain != "" {
		t.Fatalf("empty override lost, got %q", cfg.Auth.CookieDomain)
	}
}

func TestCookieDomainEnvOverride(t *testing.T) {
	d := t.TempDir()
	old, _ := os.Getwd()
	defer os.Chdir(old)
	os.Chdir(d)
	t.Setenv("BANHBAO_AUTH_COOKIE_DOMAIN", ".example.org")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Auth.CookieDomain != ".example.org" {
		t.Fatalf("env override lost, got %q", cfg.Auth.CookieDomain)
	}
}

func TestAccessDefaultsOpen(t *testing.T) {
	d := t.TempDir()
	old, _ := os.Getwd()
	defer os.Chdir(old)
	os.Chdir(d)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Auth.AllowedEmailDomains) != 0 || len(cfg.Auth.AllowedEmails) != 0 {
		t.Fatalf("allowlist not empty by default: %v %v", cfg.Auth.AllowedEmailDomains, cfg.Auth.AllowedEmails)
	}
	if cfg.Auth.SharedOrg != "" || len(cfg.Auth.OwnerEmails) != 0 {
		t.Fatalf("shared org set by default: %q %v", cfg.Auth.SharedOrg, cfg.Auth.OwnerEmails)
	}
	if cfg.Auth.DefaultRole != "operator" {
		t.Fatalf("default_role = %q", cfg.Auth.DefaultRole)
	}
}

func TestAccessFromYAML(t *testing.T) {
	d := t.TempDir()
	yaml := "auth:\n" +
		"  allowed_email_domains: [a.example, b.example]\n" +
		"  allowed_emails: [guest@c.example]\n" +
		"  shared_org: platform\n" +
		"  owner_emails: [root@a.example]\n" +
		"  default_role: viewer\n"
	os.WriteFile(d+"/config.yaml", []byte(yaml), 0o644)
	old, _ := os.Getwd()
	defer os.Chdir(old)
	os.Chdir(d)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Auth.AllowedEmailDomains) != 2 || cfg.Auth.AllowedEmailDomains[1] != "b.example" {
		t.Fatalf("allowed_email_domains = %v", cfg.Auth.AllowedEmailDomains)
	}
	if len(cfg.Auth.AllowedEmails) != 1 || cfg.Auth.AllowedEmails[0] != "guest@c.example" {
		t.Fatalf("allowed_emails = %v", cfg.Auth.AllowedEmails)
	}
	if cfg.Auth.SharedOrg != "platform" {
		t.Fatalf("shared_org = %q", cfg.Auth.SharedOrg)
	}
	if len(cfg.Auth.OwnerEmails) != 1 || cfg.Auth.OwnerEmails[0] != "root@a.example" {
		t.Fatalf("owner_emails = %v", cfg.Auth.OwnerEmails)
	}
	if cfg.Auth.DefaultRole != "viewer" {
		t.Fatalf("default_role = %q", cfg.Auth.DefaultRole)
	}
}

func TestAccessFromEnv(t *testing.T) {
	d := t.TempDir()
	old, _ := os.Getwd()
	defer os.Chdir(old)
	os.Chdir(d)
	t.Setenv("BANHBAO_AUTH_ALLOWED_EMAIL_DOMAINS", "a.example,b.example")
	t.Setenv("BANHBAO_AUTH_OWNER_EMAILS", "root@a.example")
	t.Setenv("BANHBAO_AUTH_SHARED_ORG", "platform")
	t.Setenv("BANHBAO_AUTH_DEFAULT_ROLE", "admin")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Auth.AllowedEmailDomains) != 2 || cfg.Auth.AllowedEmailDomains[0] != "a.example" {
		t.Fatalf("allowed_email_domains = %v", cfg.Auth.AllowedEmailDomains)
	}
	if len(cfg.Auth.OwnerEmails) != 1 || cfg.Auth.SharedOrg != "platform" || cfg.Auth.DefaultRole != "admin" {
		t.Fatalf("env override lost: %v %q %q", cfg.Auth.OwnerEmails, cfg.Auth.SharedOrg, cfg.Auth.DefaultRole)
	}
}
