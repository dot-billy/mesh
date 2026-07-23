// Package postgresruntime provides the single secure construction path for a
// Mesh PostgreSQL pool and exact-document store. It accepts connection secrets
// only through postgresconfig's private DSN file loader and sanitizes errors at
// connection boundaries where pgx may retain DSN material.
package postgresruntime

import (
	"context"
	"errors"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"

	"mesh/internal/postgresconfig"
	"mesh/internal/postgresstore"
)

// Options configures the shared PostgreSQL runtime. Local plaintext is an
// explicit development/test exception; postgresconfig still restricts it to a
// parsed numeric loopback address or an absolute Unix-socket directory.
type Options struct {
	DSNFile             string
	AllowLocalPlaintext bool
	StoreOptions        postgresstore.Options
}

// Runtime owns the connection pool. Its Store is constructed over the
// caller-shared pool and therefore does not close the pool itself.
type Runtime struct {
	pool  *pgxpool.Pool
	store *postgresstore.Store
	once  sync.Once
}

// Open loads the private DSN, forces the safe search path, creates the pool,
// proves bounded connectivity to a writable route, and constructs the exact
// document store. Migration remains an explicit operator action.
func Open(ctx context.Context, options Options) (*Runtime, error) {
	if ctx == nil {
		return nil, errors.New("postgres runtime context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	configOptions := postgresconfig.Options{}
	if options.AllowLocalPlaintext {
		configOptions.Transport = postgresconfig.AllowLocalPlaintext
	}
	config, err := loadConfig(options.DSNFile, configOptions)
	if err != nil {
		return nil, err
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, errors.New("open PostgreSQL pool failed")
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			pool.Close()
		}
	}()

	pingCtx, cancel := context.WithTimeout(ctx, config.PingTimeout)
	err = pool.Ping(pingCtx)
	cancel()
	if err != nil {
		if contextErr := pingCtx.Err(); contextErr != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("ping PostgreSQL pool failed")
	}
	store, err := postgresstore.New(pool, options.StoreOptions)
	if err != nil {
		return nil, err
	}
	closeOnError = false
	return &Runtime{pool: pool, store: store}, nil
}

func loadConfig(path string, options postgresconfig.Options) (*pgxpool.Config, error) {
	config, err := postgresconfig.LoadFile(path, options)
	if err != nil {
		return nil, err
	}
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = make(map[string]string)
	}
	// All Mesh queries schema-qualify application objects. This also blocks a
	// caller-controlled object from shadowing built-in functions or types.
	config.ConnConfig.RuntimeParams["search_path"] = "pg_catalog"
	return config, nil
}

// Pool returns the owned pool for components that need pgx-native access.
// Callers must not close it directly; close Runtime instead.
func (runtime *Runtime) Pool() *pgxpool.Pool {
	if runtime == nil {
		return nil
	}
	return runtime.pool
}

// Store returns the shared exact-document store.
func (runtime *Runtime) Store() *postgresstore.Store {
	if runtime == nil {
		return nil
	}
	return runtime.store
}

// Close is idempotent. It closes the logical Store before the owned pool.
func (runtime *Runtime) Close() error {
	if runtime == nil {
		return nil
	}
	var result error
	runtime.once.Do(func() {
		if runtime.store != nil {
			result = runtime.store.Close()
		}
		if runtime.pool != nil {
			runtime.pool.Close()
		}
	})
	return result
}
