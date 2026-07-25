// Package postgresconfig loads a PostgreSQL pool configuration from a private
// on-disk DSN. It deliberately does not accept a DSN value from an argument or
// environment variable so credentials do not become process metadata.
package postgresconfig

import (
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// MaxDSNFileBytes bounds both allocation and parsing work for the secret
	// configuration file.
	MaxDSNFileBytes = 16 << 10
	maxPathBytes    = 4096

	defaultPingTimeout = 5 * time.Second
	minPingTimeout     = 100 * time.Millisecond
	maxPingTimeout     = 30 * time.Second

	minConnectTimeout = time.Second
	maxConnectTimeout = 30 * time.Second
	maxPoolConns      = int32(128)

	minConnLifetime   = time.Minute
	maxConnLifetime   = 24 * time.Hour
	minConnIdleTime   = time.Second
	maxConnIdleTime   = 2 * time.Hour
	minHealthPeriod   = time.Second
	maxHealthPeriod   = 5 * time.Minute
	maxLifetimeJitter = time.Hour
)

// TransportPolicy controls the only supported relaxation of the production
// transport policy.
type TransportPolicy uint8

const (
	// RequireAuthenticatedTLS is the production default. Every primary and
	// fallback route must authenticate the server hostname with TLS.
	RequireAuthenticatedTLS TransportPolicy = iota
	// AllowLocalPlaintext permits a non-TLS route only when its parsed host is a
	// numeric loopback address or an absolute Unix-socket directory.
	AllowLocalPlaintext
)

// Options are typed so callers must make the local plaintext exception
// explicit. A zero Options value is production-safe.
type Options struct {
	Transport   TransportPolicy
	PingTimeout time.Duration
}

// Stage identifies a generic failure boundary without retaining an underlying
// error that might contain the DSN, password, or a parsed credential value.
type Stage string

const (
	StageOptions     Stage = "options"
	StagePlatform    Stage = "platform"
	StagePath        Stage = "path"
	StageOpen        Stage = "open"
	StageMetadata    Stage = "metadata"
	StageRead        Stage = "read"
	StageFormat      Stage = "format"
	StageEnvironment Stage = "environment"
	StageParse       Stage = "parse"
	StageTransport   Stage = "transport"
	StagePool        Stage = "pool"
)

// Error intentionally contains only a stage. In particular, it never wraps a
// pgx parsing error because pgx parse errors can retain the entire DSN.
type Error struct {
	Stage Stage
}

func (e *Error) Error() string {
	return "postgres configuration rejected at " + string(e.Stage) + " stage"
}

func stageError(stage Stage) error { return &Error{Stage: stage} }

var (
	errUnsupported = errors.New("unsupported platform")
	errOpen        = errors.New("secure open failed")
	errMetadata    = errors.New("file metadata rejected")
	errRead        = errors.New("stable read failed")
)

// LoadFile loads and validates a pool configuration from path. The returned
// value is ready for pgxpool.NewWithConfig. The DSN itself is accepted only via
// the private file at path.
//
// All configurations require target_session_attrs=read-write and reject
// arbitrary PostgreSQL runtime parameters. The production transport requires
// sslmode=verify-full with sslrootcert=system. See AllowLocalPlaintext for the
// only supported exception.
func LoadFile(path string, opts Options) (*pgxpool.Config, error) {
	return loadFile(path, opts, nil)
}

func loadFile(path string, opts Options, afterFirstRead func()) (*pgxpool.Config, error) {
	pingTimeout, err := validateOptions(opts)
	if err != nil {
		return nil, err
	}
	if err := validatePath(path); err != nil {
		return nil, err
	}

	raw, err := readPrivateFile(path, afterFirstRead)
	if err != nil {
		switch {
		case errors.Is(err, errUnsupported):
			return nil, stageError(StagePlatform)
		case errors.Is(err, errOpen):
			return nil, stageError(StageOpen)
		case errors.Is(err, errMetadata):
			return nil, stageError(StageMetadata)
		default:
			return nil, stageError(StageRead)
		}
	}
	defer clear(raw)

	dsnBytes, err := validateLine(raw)
	if err != nil {
		return nil, stageError(StageFormat)
	}
	settings, err := inspectDSN(string(dsnBytes))
	if err != nil {
		return nil, stageError(StageParse)
	}
	if err := validateDSNSettings(settings); err != nil {
		return nil, stageError(StageParse)
	}
	if err := rejectAmbientPostgresEnvironment(); err != nil {
		return nil, stageError(StageEnvironment)
	}

	// pgx errors retain their input connection string. Discard them at this
	// boundary and return only the generic stage error above.
	config, err := pgxpool.ParseConfig(string(dsnBytes))
	if err != nil {
		return nil, stageError(StageParse)
	}
	if err := validateNoAmbientConfig(config, settings); err != nil {
		return nil, stageError(StageParse)
	}
	if err := validateTransport(config, settings, opts.Transport); err != nil {
		return nil, stageError(StageTransport)
	}
	if err := validatePool(config, pingTimeout); err != nil {
		return nil, stageError(StagePool)
	}

	return config, nil
}

func validateOptions(opts Options) (time.Duration, error) {
	if opts.Transport != RequireAuthenticatedTLS && opts.Transport != AllowLocalPlaintext {
		return 0, stageError(StageOptions)
	}
	pingTimeout := opts.PingTimeout
	if pingTimeout == 0 {
		pingTimeout = defaultPingTimeout
	}
	if pingTimeout < minPingTimeout || pingTimeout > maxPingTimeout {
		return 0, stageError(StageOptions)
	}
	return pingTimeout, nil
}

func validatePath(path string) error {
	if path == "" || len(path) > maxPathBytes || !utf8.ValidString(path) {
		return stageError(StagePath)
	}
	for _, r := range path {
		if unicode.IsControl(r) {
			return stageError(StagePath)
		}
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return stageError(StagePath)
	}
	if path == string(filepath.Separator) || filepath.Base(path) == "." || filepath.Base(path) == ".." {
		return stageError(StagePath)
	}
	return nil
}

func validateLine(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > MaxDSNFileBytes || !utf8.Valid(raw) {
		return nil, errors.New("invalid line")
	}
	line := raw
	if line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}
	if len(line) == 0 || line[0] == ' ' || line[len(line)-1] == ' ' {
		return nil, errors.New("invalid line")
	}
	for _, r := range string(line) {
		if unicode.IsControl(r) {
			return nil, errors.New("invalid line")
		}
	}
	return line, nil
}

var postgresEnvironmentKeys = [...]string{
	"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPASSFILE",
	"PGSERVICE", "PGSERVICEFILE", "PGSSLMODE", "PGSSLCERT", "PGSSLKEY",
	"PGSSLROOTCERT", "PGSSLPASSWORD", "PGSSLSNI", "PGSSLNEGOTIATION",
	"PGAPPNAME", "PGCONNECT_TIMEOUT", "PGTARGETSESSIONATTRS", "PGTZ",
	"PGOPTIONS", "PGMINPROTOCOLVERSION", "PGMAXPROTOCOLVERSION",
	"PGCHANNELBINDING", "PGREQUIREAUTH",
}

func rejectAmbientPostgresEnvironment() error {
	for _, key := range postgresEnvironmentKeys {
		if value, ok := os.LookupEnv(key); ok && value != "" {
			return errors.New("ambient postgres setting")
		}
	}
	return nil
}

func validateNoAmbientConfig(config *pgxpool.Config, settings map[string]string) error {
	password, passwordPresent := settings["password"]
	if passwordPresent {
		if config.ConnConfig.Password != password {
			return errors.New("password source mismatch")
		}
	} else if config.ConnConfig.Password != "" {
		// A password appeared from the default passfile rather than the DSN.
		return errors.New("ambient password rejected")
	}

	if config.ConnConfig.ValidateConnect == nil {
		return errors.New("read-write routing validator missing")
	}
	if len(config.ConnConfig.RuntimeParams) != 0 {
		return errors.New("runtime parameters rejected")
	}
	if config.ConnConfig.SSLNegotiation != "" || config.ConnConfig.KerberosSrvName != "" || config.ConnConfig.KerberosSpn != "" {
		return errors.New("ambient negotiation setting rejected")
	}
	if config.ConnConfig.MinProtocolVersion != "3.0" || config.ConnConfig.MaxProtocolVersion != "3.0" {
		return errors.New("ambient protocol setting rejected")
	}
	if config.ConnConfig.ChannelBinding != "prefer" || config.ConnConfig.RequireAuth != "" {
		return errors.New("ambient authentication setting rejected")
	}
	for _, route := range connectionRoutes(config) {
		if route.tls == nil {
			continue
		}
		if route.tls.RootCAs == nil {
			return errors.New("explicit system root pool missing")
		}
		if len(route.tls.Certificates) != 0 {
			return errors.New("client certificate rejected")
		}
	}
	return nil
}

var allowedDSNSettings = map[string]struct{}{
	"host":                          {},
	"port":                          {},
	"database":                      {},
	"user":                          {},
	"password":                      {},
	"connect_timeout":               {},
	"sslmode":                       {},
	"sslrootcert":                   {},
	"target_session_attrs":          {},
	"pool_max_conns":                {},
	"pool_min_conns":                {},
	"pool_min_idle_conns":           {},
	"pool_max_conn_lifetime":        {},
	"pool_max_conn_idle_time":       {},
	"pool_health_check_period":      {},
	"pool_max_conn_lifetime_jitter": {},
}

func validateDSNSettings(settings map[string]string) error {
	for _, key := range []string{"host", "user", "database", "connect_timeout", "sslmode", "target_session_attrs"} {
		if settings[key] == "" {
			return errors.New("required setting missing")
		}
	}
	for key := range settings {
		if _, ok := allowedDSNSettings[key]; !ok {
			return errors.New("setting rejected")
		}
	}
	if settings["target_session_attrs"] != "read-write" {
		return errors.New("read-write routing required")
	}
	switch settings["sslmode"] {
	case "verify-full":
		if settings["sslrootcert"] != "system" {
			return errors.New("system roots required")
		}
	case "disable":
		if _, ok := settings["sslrootcert"]; ok {
			return errors.New("root setting rejected for plaintext")
		}
	}
	return nil
}

type connectionRoute struct {
	host string
	port uint16
	tls  *tls.Config
}

func connectionRoutes(config *pgxpool.Config) []connectionRoute {
	routes := make([]connectionRoute, 0, len(config.ConnConfig.Fallbacks)+1)
	routes = append(routes, connectionRoute{
		host: config.ConnConfig.Host,
		port: config.ConnConfig.Port,
		tls:  config.ConnConfig.TLSConfig,
	})
	for _, fallback := range config.ConnConfig.Fallbacks {
		if fallback == nil {
			routes = append(routes, connectionRoute{})
			continue
		}
		routes = append(routes, connectionRoute{
			host: fallback.Host,
			port: fallback.Port,
			tls:  fallback.TLSConfig,
		})
	}
	return routes
}

func validateTransport(config *pgxpool.Config, settings map[string]string, policy TransportPolicy) error {
	sslmode := settings["sslmode"]
	switch policy {
	case RequireAuthenticatedTLS:
		if sslmode != "verify-full" {
			return errors.New("ssl mode rejected")
		}
	case AllowLocalPlaintext:
		if sslmode != "verify-full" && sslmode != "disable" {
			return errors.New("ssl mode rejected")
		}
	default:
		return errors.New("transport policy rejected")
	}

	for _, route := range connectionRoutes(config) {
		if route.host == "" || route.port == 0 {
			return errors.New("empty route")
		}
		if route.tls != nil {
			if route.tls.InsecureSkipVerify || route.tls.ServerName == "" {
				return errors.New("unauthenticated tls")
			}
			if route.tls.MinVersion == 0 || route.tls.MinVersion < tls.VersionTLS12 {
				route.tls.MinVersion = tls.VersionTLS12
			}
			continue
		}
		if policy != AllowLocalPlaintext || !isLocalRoute(route.host, route.port) {
			return errors.New("plaintext route rejected")
		}
	}
	return nil
}

func isLocalRoute(host string, port uint16) bool {
	if network, _ := pgconn.NetworkAddress(host, port); network == "unix" {
		return filepath.IsAbs(host) && filepath.Clean(host) == host
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validatePool(config *pgxpool.Config, pingTimeout time.Duration) error {
	connectTimeout := config.ConnConfig.ConnectTimeout
	if connectTimeout < minConnectTimeout || connectTimeout > maxConnectTimeout {
		return errors.New("connect timeout rejected")
	}
	if config.MaxConns < 1 || config.MaxConns > maxPoolConns {
		return errors.New("max connections rejected")
	}
	if config.MinConns < 0 || config.MinConns > config.MaxConns {
		return errors.New("min connections rejected")
	}
	if config.MinIdleConns < 0 || config.MinIdleConns > config.MaxConns {
		return errors.New("min idle connections rejected")
	}
	if config.MaxConnLifetime < minConnLifetime || config.MaxConnLifetime > maxConnLifetime {
		return errors.New("connection lifetime rejected")
	}
	if config.MaxConnIdleTime < minConnIdleTime || config.MaxConnIdleTime > maxConnIdleTime {
		return errors.New("idle timeout rejected")
	}
	if config.HealthCheckPeriod < minHealthPeriod || config.HealthCheckPeriod > maxHealthPeriod {
		return errors.New("health period rejected")
	}
	if config.MaxConnLifetimeJitter < 0 || config.MaxConnLifetimeJitter > maxLifetimeJitter || config.MaxConnLifetimeJitter > config.MaxConnLifetime || config.MaxConnLifetimeJitter > maxConnLifetime-config.MaxConnLifetime {
		return errors.New("lifetime jitter rejected")
	}
	config.PingTimeout = pingTimeout
	return nil
}

func inspectDSN(dsn string) (map[string]string, error) {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		return inspectURLDSN(dsn)
	}
	return inspectKeywordDSN(dsn)
}

func inspectURLDSN(dsn string) (map[string]string, error) {
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Opaque != "" || u.Fragment != "" || strings.Contains(dsn, "#") || u.Host == "" {
		return nil, errors.New("invalid url dsn")
	}
	settings := make(map[string]string)
	settings["host"] = u.Host
	if u.User != nil {
		if user := u.User.Username(); user != "" {
			settings["user"] = user
		}
		if password, ok := u.User.Password(); ok {
			settings["password"] = password
		}
	}
	if database := strings.TrimLeft(u.Path, "/"); database != "" {
		settings["database"] = database
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, errors.New("invalid url query")
	}
	for key, values := range query {
		key = canonicalSettingKey(key)
		if !validSettingKey(key) || len(values) != 1 {
			return nil, errors.New("ambiguous url setting")
		}
		if _, exists := settings[key]; exists {
			return nil, errors.New("duplicate url setting")
		}
		if containsControl(key) || containsControl(values[0]) {
			return nil, errors.New("control in url setting")
		}
		settings[key] = values[0]
	}
	for key, value := range settings {
		if containsControl(key) || containsControl(value) {
			return nil, errors.New("control in url setting")
		}
	}
	return settings, nil
}

func inspectKeywordDSN(dsn string) (map[string]string, error) {
	settings := make(map[string]string)
	for i := 0; i < len(dsn); {
		for i < len(dsn) && dsn[i] == ' ' {
			i++
		}
		if i == len(dsn) {
			break
		}

		keyStart := i
		for i < len(dsn) && dsn[i] != '=' {
			i++
		}
		if i == len(dsn) {
			return nil, errors.New("missing equals")
		}
		key := strings.TrimSpace(dsn[keyStart:i])
		key = canonicalSettingKey(key)
		if !validSettingKey(key) {
			return nil, errors.New("invalid setting key")
		}
		i++
		for i < len(dsn) && dsn[i] == ' ' {
			i++
		}

		var value strings.Builder
		if i < len(dsn) && dsn[i] == '\'' {
			i++
			closed := false
			for i < len(dsn) {
				switch dsn[i] {
				case '\\':
					i++
					if i == len(dsn) {
						return nil, errors.New("invalid escape")
					}
					value.WriteByte(dsn[i])
					i++
				case '\'':
					i++
					closed = true
				default:
					value.WriteByte(dsn[i])
					i++
				}
				if closed {
					break
				}
			}
			if !closed || (i < len(dsn) && dsn[i] != ' ') {
				return nil, errors.New("invalid quoted value")
			}
		} else {
			for i < len(dsn) && dsn[i] != ' ' {
				if dsn[i] == '\\' {
					i++
					if i == len(dsn) {
						return nil, errors.New("invalid escape")
					}
				}
				value.WriteByte(dsn[i])
				i++
			}
		}

		if _, exists := settings[key]; exists {
			return nil, errors.New("duplicate setting")
		}
		if containsControl(value.String()) {
			return nil, errors.New("control in setting")
		}
		settings[key] = value.String()
	}
	if len(settings) == 0 {
		return nil, errors.New("empty settings")
	}
	return settings, nil
}

func canonicalSettingKey(key string) string {
	if key == "dbname" {
		return "database"
	}
	return key
}

func validSettingKey(key string) bool {
	if key == "" || key[0] < 'a' || key[0] > 'z' {
		return false
	}
	for i := 1; i < len(key); i++ {
		if (key[i] < 'a' || key[i] > 'z') && (key[i] < '0' || key[i] > '9') && key[i] != '_' {
			return false
		}
	}
	return true
}

func containsControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}
