package main

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	pahov3 "github.com/eclipse/paho.mqtt.golang"
	"github.com/eclipse/paho.golang/autopaho"
	pahov5 "github.com/eclipse/paho.golang/paho"
	"filippo.io/edwards25519"
	mqttserver "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/listeners"
	"github.com/mochi-mqtt/server/v2/packets"
)

// ── JWT / crypto ──────────────────────────────────────────────────────────────

const jwtHeaderJSON = `{"alg":"Ed25519","typ":"JWT"}`

// jwtPayload mirrors MeshCore's token payload field order exactly.
type jwtPayload struct {
	PublicKey string `json:"publicKey"`
	Iat       int64  `json:"iat"`
	Exp       int64  `json:"exp"`
	Aud       string `json:"aud"`
	Owner     string `json:"owner"`
	Client    string `json:"client"`
	Email     string `json:"email,omitempty"`
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signExpanded signs message with MeshCore's expanded Ed25519 key format.
// expandedKey = scalar (32 bytes) || prefix (32 bytes) — SHA-512 of seed, clamped.
// Signature is returned as 64 raw bytes (caller hex-encodes per MeshCore convention).
func signExpanded(message, expandedKey, publicKey []byte) ([]byte, error) {
	scalar, prefix := expandedKey[:32], expandedKey[32:]

	// r = SHA-512(prefix || message), reduced mod l
	h := sha512.New()
	h.Write(prefix)
	h.Write(message)
	r, err := new(edwards25519.Scalar).SetUniformBytes(h.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("nonce reduction: %w", err)
	}

	// R = r·B
	R := new(edwards25519.Point).ScalarBaseMult(r)

	// k = SHA-512(R || A || message), reduced mod l
	h.Reset()
	h.Write(R.Bytes())
	h.Write(publicKey)
	h.Write(message)
	k, err := new(edwards25519.Scalar).SetUniformBytes(h.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("challenge reduction: %w", err)
	}

	// a = clamped scalar from expanded key
	a, err := new(edwards25519.Scalar).SetBytesWithClamping(scalar)
	if err != nil {
		return nil, fmt.Errorf("scalar decode: %w", err)
	}

	// S = (r + k·a) mod l
	S := new(edwards25519.Scalar).MultiplyAdd(k, a, r)

	sig := make([]byte, 64)
	copy(sig[:32], R.Bytes())
	copy(sig[32:], S.Bytes())
	return sig, nil
}

// generateJWT mints a fresh MeshCore JWT.
// Token format: header_b64url.payload_b64url.signature_hex  (non-standard; hex sig)
func generateJWT(expandedPrivKey, publicKey []byte, audience, email, clientStr string, lifetime int64) (string, error) {
	now := time.Now().Unix()
	pubHex := strings.ToUpper(hex.EncodeToString(publicKey))

	payload, err := json.Marshal(jwtPayload{
		PublicKey: pubHex,
		Iat:       now,
		Exp:       now + lifetime,
		Aud:       audience,
		Owner:     pubHex,
		Client:    clientStr,
		Email:     email,
	})
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}

	signingInput := b64u([]byte(jwtHeaderJSON)) + "." + b64u(payload)
	sig, err := signExpanded([]byte(signingInput), expandedPrivKey, publicKey)
	if err != nil {
		return "", err
	}
	return signingInput + "." + hex.EncodeToString(sig), nil
}

// ── Config ────────────────────────────────────────────────────────────────────

// KeyEntry holds one node's Ed25519 keypair and optional email for JWT.
type KeyEntry struct {
	PrivKey []byte // 64-byte expanded Ed25519 key
	PubKey  []byte // 32-byte Ed25519 public key
	Email   string
}

type TCPBrokerConfig struct {
	Addr string
	User string
	Pass string
}

type Config struct {
	TCPBrokers    []TCPBrokerConfig
	WSBrokerURLs  []string
	Keys          map[string]KeyEntry // pubkey_hex_upper → KeyEntry
	TokenLifetime int64               // seconds
	TokenClient   string              // "client" claim in JWT
	LocalListen   string
	LocalUser     string // empty = allow any credentials
	LocalPass     string
	LogLevel      string
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// loadKeys scans MESHCORE_KEY_0_*, MESHCORE_KEY_1_*, … until an index has
// neither PUBLIC nor PRIVATE set. Each keypair is validated (derived pubkey
// must match provided pubkey). Returns a map keyed by uppercase pubkey hex.
func loadKeys(logger *slog.Logger) (map[string]KeyEntry, error) {
	keys := make(map[string]KeyEntry)
	for i := 0; ; i++ {
		prefix := fmt.Sprintf("MESHCORE_KEY_%d_", i)
		pubHex := os.Getenv(prefix + "PUBLIC")
		privHex := os.Getenv(prefix + "PRIVATE")
		if pubHex == "" && privHex == "" {
			break
		}
		if pubHex == "" || privHex == "" {
			return nil, fmt.Errorf("%s: both PUBLIC and PRIVATE must be set", prefix)
		}

		privKey, err := hex.DecodeString(privHex)
		if err != nil {
			return nil, fmt.Errorf("%sPRIVATE: invalid hex: %w", prefix, err)
		}
		if len(privKey) != 64 {
			return nil, fmt.Errorf("%sPRIVATE must be 64 bytes (128 hex chars), got %d", prefix, len(privKey))
		}

		pubKey, err := hex.DecodeString(pubHex)
		if err != nil {
			return nil, fmt.Errorf("%sPUBLIC: invalid hex: %w", prefix, err)
		}
		if len(pubKey) != 32 {
			return nil, fmt.Errorf("%sPUBLIC must be 32 bytes (64 hex chars), got %d", prefix, len(pubKey))
		}

		// Verify keypair consistency.
		a, err := new(edwards25519.Scalar).SetBytesWithClamping(privKey[:32])
		if err != nil {
			return nil, fmt.Errorf("%sPRIVATE: invalid scalar: %w", prefix, err)
		}
		derived := new(edwards25519.Point).ScalarBaseMult(a).Bytes()
		if !bytes.Equal(derived, pubKey) {
			return nil, fmt.Errorf("%s: key pair mismatch — derived pubkey %s does not match %s",
				prefix,
				strings.ToUpper(hex.EncodeToString(derived)),
				strings.ToUpper(hex.EncodeToString(pubKey)),
			)
		}

		pubHexUpper := strings.ToUpper(hex.EncodeToString(pubKey))
		keys[pubHexUpper] = KeyEntry{
			PrivKey: privKey,
			PubKey:  pubKey,
			Email:   os.Getenv(prefix + "EMAIL"),
		}
		logger.Info("key pair OK", "index", i, "pubkey", pubHexUpper)
	}
	return keys, nil
}

func loadConfig(logger *slog.Logger) (Config, error) {
	lifetimeStr := getenv("TOKEN_LIFETIME", "3300")
	lifetime, err := strconv.ParseInt(lifetimeStr, 10, 64)
	if err != nil {
		return Config{}, fmt.Errorf("invalid TOKEN_LIFETIME %q: %w", lifetimeStr, err)
	}

	keys, err := loadKeys(logger)
	if err != nil {
		return Config{}, err
	}

	var tcpBrokers []TCPBrokerConfig
	for i := 0; ; i++ {
		addr := os.Getenv(fmt.Sprintf("MQTT_BROKER_%d_ADDR", i))
		if addr == "" {
			break
		}
		tcpBrokers = append(tcpBrokers, TCPBrokerConfig{
			Addr: addr,
			User: os.Getenv(fmt.Sprintf("MQTT_BROKER_%d_USER", i)),
			Pass: os.Getenv(fmt.Sprintf("MQTT_BROKER_%d_PASS", i)),
		})
	}

	var wsURLs []string
	for i := 0; ; i++ {
		u := os.Getenv(fmt.Sprintf("WS_BROKER_%d_URL", i))
		if u == "" {
			break
		}
		wsURLs = append(wsURLs, u)
	}

	return Config{
		TCPBrokers:    tcpBrokers,
		WSBrokerURLs:  wsURLs,
		Keys:          keys,
		TokenLifetime: lifetime,
		TokenClient:   getenv("TOKEN_CLIENT", "mqtt-proxy/1.0"),
		LocalListen:   getenv("LOCAL_LISTEN", ":1883"),
		LocalUser:     os.Getenv("LOCAL_MQTT_USER"),
		LocalPass:     os.Getenv("LOCAL_MQTT_PASS"),
		LogLevel:      getenv("LOG_LEVEL", "info"),
	}, nil
}

func maskIfSet(s string) string {
	if s != "" {
		return "***"
	}
	return "(not set)"
}

// ── Logger ────────────────────────────────────────────────────────────────────

func buildLogger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}

// ── TCPUpstream — MQTT v3.1.1 (paho.mqtt.golang) ─────────────────────────────

type TCPUpstream struct {
	nm          string
	client      pahov3.Client
	logger      *slog.Logger
	dialOnce    sync.Once
}

func newTCPUpstream(name, brokerURL, user, pass string, logger *slog.Logger) *TCPUpstream {
	opts := pahov3.NewClientOptions()
	opts.AddBroker(brokerURL)
	if user != "" {
		opts.SetUsername(user)
	}
	if pass != "" {
		opts.SetPassword(pass)
	}
	opts.SetClientID("mqtt-proxy-" + name)
	opts.SetAutoReconnect(true)
	opts.SetConnectRetryInterval(5 * time.Second)
	opts.SetConnectTimeout(10 * time.Second)
	opts.SetKeepAlive(30 * time.Second)
	opts.SetWriteTimeout(5 * time.Second)
	opts.SetOnConnectHandler(func(_ pahov3.Client) {
		logger.Info("upstream connected", "upstream", name, "url", brokerURL, "protocol", "mqtt/3.1.1")
	})
	opts.SetConnectionLostHandler(func(_ pahov3.Client, err error) {
		logger.Warn("upstream disconnected", "upstream", name, "err", err)
	})
	opts.SetReconnectingHandler(func(_ pahov3.Client, _ *pahov3.ClientOptions) {
		logger.Info("upstream reconnecting", "upstream", name)
	})

	return &TCPUpstream{nm: name, logger: logger, client: pahov3.NewClient(opts)}
}

func (u *TCPUpstream) ensureConnected() {
	u.dialOnce.Do(func() {
		u.logger.Info("upstream connecting (lazy)", "upstream", u.nm)
		token := u.client.Connect()
		go func() {
			token.Wait()
			if err := token.Error(); err != nil {
				u.logger.Error("upstream initial connect failed", "upstream", u.nm, "err", err)
			}
		}()
	})
}

func (u *TCPUpstream) forward(topic string, qos byte, retain bool, payload []byte) {
	u.ensureConnected()
	if !u.client.IsConnected() {
		u.logger.Warn("upstream not connected, skipping", "upstream", u.nm, "topic", topic)
		return
	}
	token := u.client.Publish(topic, qos, retain, payload)
	go func() {
		token.Wait()
		if err := token.Error(); err != nil {
			u.logger.Error("forward failed", "upstream", u.nm, "topic", topic, "err", err)
		} else {
			u.logger.Debug("forwarded", "upstream", u.nm, "topic", topic)
		}
	}()
}

func (u *TCPUpstream) shutdown() {
	u.client.Disconnect(500)
	u.logger.Info("upstream disconnected cleanly", "upstream", u.nm)
}

// ── WSUpstream — MQTT v5 with JWT auth (paho.golang/autopaho) ────────────────

type WSUpstream struct {
	nm     string
	cm     *autopaho.ConnectionManager
	ctx    context.Context
	cancel context.CancelFunc
	logger *slog.Logger
}

func newWSUpstream(name, brokerURL string, expandedPrivKey, publicKey []byte, email, clientStr string, lifetime int64, logger *slog.Logger) *WSUpstream {
	ctx, cancel := context.WithCancel(context.Background())

	parsed, err := url.Parse(brokerURL)
	if err != nil {
		logger.Error("invalid upstream URL", "upstream", name, "url", brokerURL, "err", err)
		cancel()
		return nil
	}
	audience := parsed.Hostname()

	// Broker requires an explicit WebSocket path.
	if parsed.Path == "" {
		parsed.Path = "/"
	}

	cfg := autopaho.ClientConfig{
		ServerUrls:        []*url.URL{parsed},
		KeepAlive:         30,
		ConnectRetryDelay: 5 * time.Second,
		ConnectTimeout:    10 * time.Second,
		OnConnectionUp: func(_ *autopaho.ConnectionManager, _ *pahov5.Connack) {
			logger.Info("upstream connected", "upstream", name, "url", brokerURL, "protocol", "mqtt/5", "audience", audience)
		},
		OnConnectError: func(err error) {
			logger.Warn("upstream connect error", "upstream", name, "err", err)
		},
		ClientConfig: pahov5.ClientConfig{
			ClientID: name,
			OnClientError: func(err error) {
				logger.Error("upstream client error", "upstream", name, "err", err)
			},
			OnServerDisconnect: func(d *pahov5.Disconnect) {
				logger.Warn("upstream server disconnect", "upstream", name, "reason", d.ReasonCode)
			},
		},
		// Fresh JWT generated on every connection attempt so expiry is never an issue.
		ConnectPacketBuilder: func(c *pahov5.Connect, _ *url.URL) (*pahov5.Connect, error) {
			token, err := generateJWT(expandedPrivKey, publicKey, audience, email, clientStr, lifetime)
			if err != nil {
				return nil, fmt.Errorf("generate JWT for %s: %w", name, err)
			}
			pubHex := "v1_" + strings.ToUpper(hex.EncodeToString(publicKey))
			c.Username = pubHex
			c.UsernameFlag = true
			c.Password = []byte(token)
			c.PasswordFlag = true
			logger.Debug("generated JWT", "upstream", name, "audience", audience,
				"username", pubHex,
				"exp", time.Now().Add(time.Duration(lifetime)*time.Second).UTC().Format(time.RFC3339),
				"token", token)
			return c, nil
		},
	}

	cm, err := autopaho.NewConnection(ctx, cfg)
	if err != nil {
		logger.Error("failed to create upstream connection", "upstream", name, "err", err)
		cancel()
		return nil
	}

	logger.Info("upstream connecting", "upstream", name, "url", brokerURL, "protocol", "mqtt/5", "audience", audience)
	return &WSUpstream{nm: name, cm: cm, ctx: ctx, cancel: cancel, logger: logger}
}

func (u *WSUpstream) forward(topic string, qos byte, retain bool, payload []byte) {
	go func() {
		ctx, cancel := context.WithTimeout(u.ctx, 5*time.Second)
		defer cancel()
		_, err := u.cm.Publish(ctx, &pahov5.Publish{
			Topic:   topic,
			QoS:     qos,
			Retain:  retain,
			Payload: payload,
		})
		if err != nil {
			u.logger.Error("forward failed", "upstream", u.nm, "topic", topic, "err", err)
		} else {
			u.logger.Debug("forwarded", "upstream", u.nm, "topic", topic)
		}
	}()
}

func (u *WSUpstream) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = u.cm.Disconnect(ctx)
	u.cancel()
	u.logger.Info("upstream disconnected cleanly", "upstream", u.nm)
}

// ── NodeRegistry — per-node lazy WS connection management ────────────────────

// nodePair holds WS upstream connections for one node (one per configured WS broker).
type nodePair struct {
	ws []*WSUpstream
}

// NodeRegistry creates and caches per-node WS connections on first use.
type NodeRegistry struct {
	keys      map[string]KeyEntry  // pubkey_hex_upper → KeyEntry
	nodes     map[string]*nodePair // pubkey_hex_upper → active pair
	mu        sync.RWMutex
	wsURLs    []string
	lifetime  int64
	clientStr string
	logger    *slog.Logger
}

func newNodeRegistry(keys map[string]KeyEntry, wsURLs []string, lifetime int64, clientStr string, logger *slog.Logger) *NodeRegistry {
	return &NodeRegistry{
		keys:      keys,
		nodes:     make(map[string]*nodePair),
		wsURLs:    wsURLs,
		lifetime:  lifetime,
		clientStr: clientStr,
		logger:    logger,
	}
}

// getOrCreate returns the cached nodePair for pubkeyHex, creating WS connections
// on first call. Blocks until the new connections are established so the first
// publish is not dropped while the dial is in progress.
// Returns nil if pubkeyHex is not in the known-keys dictionary.
func (r *NodeRegistry) getOrCreate(pubkeyHex string) *nodePair {
	// Fast path.
	r.mu.RLock()
	pair, ok := r.nodes[pubkeyHex]
	r.mu.RUnlock()
	if ok {
		return pair
	}

	// Slow path — check registry and create.
	r.mu.Lock()

	// Double-check after acquiring write lock.
	if pair, ok = r.nodes[pubkeyHex]; ok {
		r.mu.Unlock()
		return pair
	}

	entry, known := r.keys[pubkeyHex]
	if !known {
		r.mu.Unlock()
		return nil
	}

	shortID := pubkeyHex
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}

	pair = &nodePair{}
	for i, wsURL := range r.wsURLs {
		name := fmt.Sprintf("ws-%d-%s", i, shortID)
		if up := newWSUpstream(name, wsURL, entry.PrivKey, entry.PubKey, entry.Email, r.clientStr, r.lifetime, r.logger); up != nil {
			pair.ws = append(pair.ws, up)
		}
	}
	r.nodes[pubkeyHex] = pair
	r.logger.Info("node WS connections created", "node", pubkeyHex, "count", len(pair.ws))
	r.mu.Unlock() // release before blocking on dial

	// Wait for all connections to come up before returning so the caller's
	// first forward() call doesn't hit "connection currently down".
	waitCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, up := range pair.ws {
		if err := up.cm.AwaitConnection(waitCtx); err != nil {
			r.logger.Warn("WS upstream did not connect in time for first publish", "upstream", up.nm, "err", err)
		}
	}
	return pair
}

func (r *NodeRegistry) shutdownAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for node, pair := range r.nodes {
		for _, up := range pair.ws {
			up.shutdown()
		}
		r.logger.Info("node WS connections shut down", "node", node)
	}
}

// ── Topic parsing ─────────────────────────────────────────────────────────────

// extractNodeID returns the uppercase pubkey hex from topics of the form
// meshcore/<type>/<PUBKEY_HEX>/<subtopic>, or "" if the structure doesn't match.
func extractNodeID(topic string) string {
	parts := strings.SplitN(topic, "/", 4)
	if len(parts) < 3 {
		return ""
	}
	return strings.ToUpper(parts[2])
}

// ── Auth hook ─────────────────────────────────────────────────────────────────

type AuthHook struct {
	mqttserver.HookBase
	user   string // empty = allow any
	pass   string
	logger *slog.Logger
}

func (h *AuthHook) ID() string { return "auth" }
func (h *AuthHook) Provides(b byte) bool {
	return b == mqttserver.OnConnectAuthenticate || b == mqttserver.OnACLCheck
}
func (h *AuthHook) OnACLCheck(_ *mqttserver.Client, _ string, _ bool) bool { return true }
func (h *AuthHook) OnConnectAuthenticate(cl *mqttserver.Client, pk packets.Packet) bool {
	if h.user == "" {
		h.logger.Info("device connected", "clientID", cl.ID, "remoteAddr", cl.Net.Remote)
		return true
	}
	user := string(pk.Connect.Username)
	pass := string(pk.Connect.Password)
	if user == h.user && pass == h.pass {
		h.logger.Info("device connected", "clientID", cl.ID, "remoteAddr", cl.Net.Remote)
		return true
	}
	h.logger.Warn("device rejected bad credentials", "clientID", cl.ID, "user", user)
	return false
}

// ── Forward hook ──────────────────────────────────────────────────────────────

type ForwardHook struct {
	mqttserver.HookBase
	tcps     []*TCPUpstream
	registry *NodeRegistry
	logger   *slog.Logger
}

func (h *ForwardHook) ID() string { return "forward" }
func (h *ForwardHook) Provides(b byte) bool {
	return b == mqttserver.OnPublish
}
func (h *ForwardHook) OnPublish(cl *mqttserver.Client, pk packets.Packet) (packets.Packet, error) {
	if cl == nil || strings.HasPrefix(pk.TopicName, "$SYS") {
		return pk, nil
	}
	h.logger.Debug("device publish",
		"clientID", cl.ID,
		"topic", pk.TopicName,
		"bytes", len(pk.Payload),
		"qos", pk.FixedHeader.Qos,
		"retain", pk.FixedHeader.Retain,
	)

	for _, tcp := range h.tcps {
		tcp.forward(pk.TopicName, pk.FixedHeader.Qos, pk.FixedHeader.Retain, pk.Payload)
	}

	nodeID := extractNodeID(pk.TopicName)
	if nodeID == "" {
		h.logger.Warn("cannot extract node ID from topic, WS skipped", "topic", pk.TopicName)
		return pk, nil
	}

	pair := h.registry.getOrCreate(nodeID)
	if pair == nil {
		h.logger.Warn("unknown node, WS forwarding skipped", "node", nodeID, "topic", pk.TopicName)
		return pk, nil
	}
	for _, up := range pair.ws {
		up.forward(pk.TopicName, pk.FixedHeader.Qos, pk.FixedHeader.Retain, pk.Payload)
	}
	return pk, nil
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	// Logger must exist before config validation to log errors.
	logger := buildLogger(getenv("LOG_LEVEL", "info"))

	cfg, err := loadConfig(logger)
	if err != nil {
		logger.Error("config error", "err", err)
		os.Exit(1)
	}
	// Rebuild logger with resolved level from config.
	logger = buildLogger(cfg.LogLevel)

	logger.Info("mqtt-proxy starting",
		"listen", cfg.LocalListen,
		"local_auth", cfg.LocalUser != "",
		"tcp_brokers", len(cfg.TCPBrokers),
		"ws_brokers", len(cfg.WSBrokerURLs),
		"nodes_loaded", len(cfg.Keys),
		"token_lifetime_s", cfg.TokenLifetime,
		"log_level", cfg.LogLevel,
	)

	// Waev.app (and compatible brokers) reject tokens with exp > 3600s from iat.
	if cfg.TokenLifetime > 3600 {
		logger.Warn("TOKEN_LIFETIME exceeds 3600s — Waev.app brokers will reject tokens with exp > 1 hour",
			"token_lifetime_s", cfg.TokenLifetime)
	}

	registry := newNodeRegistry(cfg.Keys, cfg.WSBrokerURLs, cfg.TokenLifetime, cfg.TokenClient, logger)

	var tcps []*TCPUpstream
	for i, b := range cfg.TCPBrokers {
		addr := b.Addr
		if !strings.Contains(addr, "://") {
			addr = "tcp://" + addr
		}
		tcps = append(tcps, newTCPUpstream(fmt.Sprintf("tcp-%d", i), addr, b.User, b.Pass, logger))
	}

	server := mqttserver.New(nil)
	if err := server.AddHook(&AuthHook{user: cfg.LocalUser, pass: cfg.LocalPass, logger: logger}, nil); err != nil {
		logger.Error("failed to add auth hook", "err", err)
		os.Exit(1)
	}
	if err := server.AddHook(&ForwardHook{tcps: tcps, registry: registry, logger: logger}, nil); err != nil {
		logger.Error("failed to add forward hook", "err", err)
		os.Exit(1)
	}

	tcpListener := listeners.NewTCP(listeners.Config{ID: "tcp", Address: cfg.LocalListen})
	if err := server.AddListener(tcpListener); err != nil {
		logger.Error("failed to add TCP listener", "err", err)
		os.Exit(1)
	}
	if err := server.Serve(); err != nil {
		logger.Error("broker serve error", "err", err)
		os.Exit(1)
	}
	logger.Info("local broker ready", "addr", cfg.LocalListen)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig

	logger.Info("shutting down")
	server.Close()
	for _, tcp := range tcps {
		tcp.shutdown()
	}
	registry.shutdownAll()
	logger.Info("stopped")
}
