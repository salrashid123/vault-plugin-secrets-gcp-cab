package gcpcab

import (
	"context"
	"sync"
	"time"

	"github.com/hashicorp/errwrap"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/oauth2/google"
)

var (
	defaultClientLifetime = 30 * time.Minute
)

type backend struct {
	*framework.Backend
	kmsClientCreateTime time.Time
	kmsClientLifetime   time.Duration
	kmsClientLock       sync.RWMutex

	creds *google.Credentials
	// ctx and ctxCancel are used to control overall plugin shutdown. These
	// contexts are given to any client libraries or requests that should be
	// terminated during plugin termination.
	ctx       context.Context
	ctxCancel context.CancelFunc
	ctxLock   sync.Mutex
}

// Factory returns a configured instance of the backend.
func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *backend) Credentials(s logical.Storage) (*google.Credentials, error) {
	// If the client already exists and is valid, return it
	b.kmsClientLock.RLock()
	if b.creds != nil && time.Now().UTC().Sub(b.kmsClientCreateTime) < b.kmsClientLifetime {
		return b.creds, nil
	}
	b.kmsClientLock.RUnlock()

	// Acquire a full lock. Since all invocations acquire a read lock and defer
	// the release of that lock, this will block until all clients are no longer
	// in use. At that point, we can acquire a globally exclusive lock to close
	// any connections and create a new client.
	b.kmsClientLock.Lock()

	b.Logger().Debug("Returning Google Credentials")

	// Attempt to close an existing client if we have one.
	b.resetClient()

	// Get the config
	config, err := b.Config(b.ctx, s)
	if err != nil {
		b.kmsClientLock.Unlock()
		return nil, err
	}

	// If credentials were provided, use those. Otherwise fall back to the
	// default application credentials.
	var creds *google.Credentials
	if config.Credentials != "" {
		b.Logger().Debug("   Using CredentialsFromJSON")
		creds, err = google.CredentialsFromJSON(b.ctx, []byte(config.Credentials), config.Scopes...)
		if err != nil {
			b.kmsClientLock.Unlock()
			return nil, errwrap.Wrapf("failed to parse credentials: {{err}}", err)
		}
	} else {
		b.Logger().Debug("   Using FindDefaultCredentials")
		creds, err = google.FindDefaultCredentials(b.ctx, config.Scopes...)
		if err != nil {
			b.kmsClientLock.Unlock()
			return nil, errwrap.Wrapf("failed to get default token source: {{err}}", err)
		}
	}
	b.creds = creds
	b.kmsClientCreateTime = time.Now().UTC()
	b.kmsClientLock.Unlock()
	return creds, nil
}

// Backend returns a configured instance of the backend.
func Backend() *backend {
	var b backend

	b.kmsClientLifetime = defaultClientLifetime
	b.ctx, b.ctxCancel = context.WithCancel(context.Background())

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help: "The GCP PrivateCA secrets engine provides issuing and revoking " +
			"certificates.",

		Paths: []*framework.Path{
			b.pathConfig(),
			b.pathCABConfigCRUD(),
			b.pathCAB(),
		},

		Invalidate: b.invalidate,
		Clean:      b.clean,
	}

	return &b
}

// clean cancels the shared contexts. This is called just before unmounting
// the plugin.
func (b *backend) clean(_ context.Context) {
	b.ctxLock.Lock()
	b.ctxCancel()
	b.ctxLock.Unlock()
}

// invalidate resets the plugin. This is called when a key is updated via
// replication.
func (b *backend) invalidate(ctx context.Context, key string) {
	switch key {
	case "config":
		b.ResetClient()
	}
}

// ResetClient closes any connected clients.
func (b *backend) ResetClient() {
	b.kmsClientLock.Lock()
	b.resetClient()
	b.kmsClientLock.Unlock()
}

// resetClient rests the underlying client. The caller is responsible for
// acquiring and releasing locks. This method is not safe to call concurrently.
func (b *backend) resetClient() {
	//b.creds = nil
	b.kmsClientCreateTime = time.Unix(0, 0).UTC()
}

// Config parses and returns the configuration data from the storage backend.
// Even when no user-defined data exists in storage, a Config is returned with
// the default values.
func (b *backend) Config(ctx context.Context, s logical.Storage) (*Config, error) {
	c := DefaultConfig()

	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, errwrap.Wrapf("failed to get configuration from storage: {{err}}", err)
	}
	if entry == nil || len(entry.Value) == 0 {
		return c, nil
	}

	if err := entry.DecodeJSON(&c); err != nil {
		return nil, errwrap.Wrapf("failed to decode configuration: {{err}}", err)
	}
	return c, nil
}
