package gcpcab

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/logical"
)

var (
	ErrKeyNotFound = errors.New("Config Key Name not found")
)

// Key represents a key from the storage backend.
type ConfigSpec struct {
	Restricted           bool           `json:"restricted"`
	TargetServiceAccount string         `json:"target_service_account"`
	Project              string         `json:"project"`
	Scopes               []string       `json:"scopes"`
	Delegates            []string       `json:"delegates"`
	Duration             int            `json:"duration"`
	Bindings             AccessBoundary `json:downscoped_options`
	RawToken             bool           `json:raw_token`
}

// Key retrieves the named key from the storage backend, or an error if one does
// not exist.
func (b *backend) CABKey(ctx context.Context, s logical.Storage, name string) (*ConfigSpec, error) {
	entry, err := s.Get(ctx, "cab/config/"+name)
	if err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("failed to retrieve issuer config %q: {{err}}", name), err)
	}
	if entry == nil {
		return nil, ErrKeyNotFound
	}

	var result ConfigSpec
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("failed to decode entry for %q: {{err}}", name), err)
	}
	return &result, nil
}

// Keys returns the list of keys
func (b *backend) CABKeys(ctx context.Context, s logical.Storage) ([]string, error) {
	entries, err := s.List(ctx, "cab/config/")
	if err != nil {
		return nil, errwrap.Wrapf("failed to list keys: {{err}}", err)
	}
	return entries, nil
}
