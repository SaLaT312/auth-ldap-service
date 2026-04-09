package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/redis/go-redis/v9"
	"gopkg.in/yaml.v3"
)

// ================= CONFIG =================

type Config struct {
	Server struct {
		Port int `yaml:"port"`
	} `yaml:"server"`

	LDAP struct {
		URL                string `yaml:"url"`
		BaseDN             string `yaml:"base_dn"`
		BindDN             string `yaml:"bind_dn"`
		BindPassword       string `yaml:"bind_password"`
		UserFilter         string `yaml:"user_filter"`
		InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	} `yaml:"ldap"`

	Redis struct {
		Addr     string `yaml:"addr"`
		Password string `yaml:"password"`
		DB       int    `yaml:"db"`
	} `yaml:"redis"`

	Session struct {
		TTLMinutes int    `yaml:"ttl_minutes"`
		CookieName string `yaml:"cookie_name"`
		Secure     bool   `yaml:"secure"`
	} `yaml:"session"`

	Auth struct {
		AllowedUsers []string `yaml:"allowed_users"`
	} `yaml:"auth"`

	Logging struct {
		Format   string   `yaml:"format"`
		Output   []string `yaml:"output"`
		FilePath string   `yaml:"file_path"`
	} `yaml:"logging"`
}

var (
	cfg    Config
	rdb    *redis.Client
	ctx    = context.Background()
	logger *log.Logger
)

// ================= MAIN =================

func main() {
	loadConfig()
	initLogger()

	rdb = redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

	http.HandleFunc("/auth_check", authHandler)
	http.HandleFunc("/auth", validateSession)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/login", loginPageHandler)

	addr := ":" + strconv.Itoa(cfg.Server.Port)
	logger.Println("Auth service started on", addr)

	err := http.ListenAndServe(addr, nil)
	if err != nil {
		logger.Fatalf("server failed: %v", err)
	}
}

// ================= LOGGER =================

type LogEntry struct {
	Time   string `json:"time"`
	IP     string `json:"ip"`
	User   string `json:"user"`
	Status string `json:"status"`
}

func initLogger() {
	var writers []io.Writer

	for _, o := range cfg.Logging.Output {
		if o == "stdout" {
			writers = append(writers, os.Stdout)
		}
		if o == "file" {
			f, err := os.OpenFile(cfg.Logging.FilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				log.Fatal(err)
			}
			writers = append(writers, f)
		}
	}

	mw := io.MultiWriter(writers...)
	logger = log.New(mw, "", 0)
}

func writeLog(ip, user, status string) {
	entry := LogEntry{
		Time:   time.Now().Format(time.RFC3339),
		IP:     ip,
		User:   user,
		Status: status,
	}

	if cfg.Logging.Format == "json" {
		b, _ := json.Marshal(entry)
		logger.Println(string(b))
	} else {
		line := fmt.Sprintf("%s - %s [%s] \"%s\"",
			ip,
			user,
			entry.Time,
			status,
		)
		logger.Println(line)
	}
}

// ================= LOGIN PAGE =================

func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	orig := r.Header.Get("X-Original-URI")
	if orig != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "REDIRECT_AFTER_LOGIN",
			Value:    orig,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   300,
		})
	}

	html := `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Login</title>
<style>
body { font-family: Arial; background:#0f172a; color:#e5e7eb; display:flex; justify-content:center; align-items:center; height:100vh; }
.box { background:#020617; padding:30px; border-radius:12px; width:320px; box-shadow:0 10px 30px rgba(0,0,0,.5); }
input, button { width:100%; padding:10px; margin-top:10px; border-radius:6px; border:none; }
input { background:#020617; color:#e5e7eb; border:1px solid #1e293b; }
button { background:#2563eb; color:white; font-weight:bold; cursor:pointer; }
.error { color:#f87171; margin-top:10px; display:none; }
.progress { color:#93c5fd; margin-top:10px; display:none; }
</style>
</head>
<body>
<div class="box">
<h2>🔐 Secure Login</h2>

<form id="loginForm">
  <input id="login" type="text" placeholder="Login" required>
  <input id="password" type="password" placeholder="Password" required>
  <button type="submit">Login</button>
</form>

<div id="progress" class="progress">In Progress....</div>
<div id="err" class="error">Authentication failed</div>
</div>

<script>
document.getElementById("loginForm").addEventListener("submit", async function(e) {
  e.preventDefault();

  document.getElementById("err").style.display = "none";
  document.getElementById("progress").style.display = "block";

  const login = document.getElementById("login").value;
  const password = document.getElementById("password").value;

  const basic = btoa(login + ":" + password);

  const res = await fetch("/auth_check", {
    method: "POST",
    headers: {
      "Authorization": "Basic " + basic
    },
    credentials: "include"
  });

  document.getElementById("progress").style.display = "none";

  if (res.status === 200) {
    window.location.href = "/";
  } else {
    document.getElementById("err").style.display = "block";
  }
});
</script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// ================= AUTH =================

func authHandler(w http.ResponseWriter, r *http.Request) {
	ip := getIP(r)

	login, password, ok := parseBasicAuth(r)
	if !ok {
		writeLog(ip, "-", "fail")
		http.Error(w, "Unauthorized", 401)
		return
	}

	if !isAllowedUser(login) {
		writeLog(ip, login, "fail")
		http.Error(w, "Forbidden", 403)
		return
	}

	dn, err := ldapFindUserDN(login)
	if err != nil {
		writeLog(ip, login, "fail")
		http.Error(w, "Unauthorized", 401)
		return
	}

	if err := ldapBindAsUser(dn, password); err != nil {
		writeLog(ip, login, "fail")
		http.Error(w, "Unauthorized", 401)
		return
	}

	writeLog(ip, login, "success")

	sessionID := createSession(login, r)

	http.SetCookie(w, &http.Cookie{
		Name:     cfg.Session.CookieName,
		Value:    sessionID,
		HttpOnly: true,
		Path:     "/",
		MaxAge:   cfg.Session.TTLMinutes * 60,
		Secure:   cfg.Session.Secure,
	})

	w.WriteHeader(200)
}

// ================= LDAP =================

func ldapConnect() (*ldap.Conn, error) {
	if strings.HasPrefix(cfg.LDAP.URL, "ldaps://") {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: cfg.LDAP.InsecureSkipVerify,
		}
		return ldap.DialURL(cfg.LDAP.URL, ldap.DialWithTLSConfig(tlsConfig))
	}
	return ldap.DialURL(cfg.LDAP.URL)
}

func ldapFindUserDN(username string) (string, error) {
	l, err := ldapConnect()
	if err != nil {
		return "", err
	}
	defer l.Close()

	l.Bind(cfg.LDAP.BindDN, cfg.LDAP.BindPassword)

	filter := strings.Replace(cfg.LDAP.UserFilter, "%s", username, 1)

	res, err := l.Search(ldap.NewSearchRequest(
		cfg.LDAP.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		filter,
		[]string{"dn"},
		nil,
	))

	if err != nil || len(res.Entries) == 0 {
		return "", fmt.Errorf("user not found")
	}

	return res.Entries[0].DN, nil
}

func ldapBindAsUser(dn, password string) error {
	l, err := ldapConnect()
	if err != nil {
		return err
	}
	defer l.Close()

	return l.Bind(dn, password)
}

// ================= SESSION =================

func validateSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(cfg.Session.CookieName)
	if err != nil {
		http.Error(w, "Unauthorized", 401)
		return
	}

	data, _ := rdb.HGetAll(ctx, "session:"+cookie.Value).Result()
	if len(data) == 0 {
		http.Error(w, "Unauthorized", 401)
		return
	}

	if data["fingerprint"] != fingerprint(r) {
		deleteSession(cookie.Value, data["username"])
		http.Error(w, "Unauthorized", 401)
		return
	}

	w.WriteHeader(200)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(cfg.Session.CookieName)
	if err == nil {
		data, _ := rdb.HGetAll(ctx, "session:"+cookie.Value).Result()
		if len(data) > 0 {
			deleteSession(cookie.Value, data["username"])
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:   cfg.Session.CookieName,
		Value:  "",
		MaxAge: -1,
		Path:   "/",
	})

	w.WriteHeader(200)
}

func createSession(username string, r *http.Request) string {
	old, _ := rdb.Get(ctx, "user:"+username).Result()
	if old != "" {
		deleteSession(old, username)
	}

	id := generateSessionID(username)
	fp := fingerprint(r)

	ttl := time.Duration(cfg.Session.TTLMinutes) * time.Minute

	rdb.HSet(ctx, "session:"+id, map[string]interface{}{
		"username":    username,
		"fingerprint": fp,
	})

	rdb.Expire(ctx, "session:"+id, ttl)
	rdb.Set(ctx, "user:"+username, id, ttl)

	return id
}

func deleteSession(id, user string) {
	rdb.Del(ctx, "session:"+id)
	rdb.Del(ctx, "user:"+user)
}

// ================= HELPERS =================

func getIP(r *http.Request) string {
	ip := r.Header.Get("X-Real-IP")
	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	return ip
}

func fingerprint(r *http.Request) string {
	data := getIP(r) + "|" + r.UserAgent()
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

func generateSessionID(username string) string {
	h := sha256.Sum256([]byte(username + time.Now().String()))
	return hex.EncodeToString(h[:])
}

func parseBasicAuth(r *http.Request) (string, string, bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		return "", "", false
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}

	return parts[0], parts[1], true
}

func isAllowedUser(u string) bool {
	for _, a := range cfg.Auth.AllowedUsers {
		if a == u {
			return true
		}
	}
	return false
}

func loadConfig() {

	configFileName, ok := os.LookupEnv("AUTH_LDAP_CONFIG_FILE_NAME")
	if !ok {
		configFileName = "config.yaml"
	}

	f, err := os.ReadFile(configFileName)
	if err != nil {
		log.Fatal(err)
	}
	yaml.Unmarshal(f, &cfg)
}
