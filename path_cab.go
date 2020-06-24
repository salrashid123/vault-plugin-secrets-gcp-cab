package gcpcab

import (
	"context"
	"encoding/json"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	sal "github.com/salrashid123/oauth2/google"
)

func (b *backend) pathCAB() *framework.Path {
	return &framework.Path{
		Pattern: "cab/" + framework.GenericNameRegex("name"),

		HelpSynopsis:    "Generate PrivateCA Keypair",
		HelpDescription: `Generate a Private CA Keypair and return them to the client`,

		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Certificate Name value`,
			},
			"config": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `PrivateCA Config Reference`,
			},
			"duration": &framework.FieldSchema{
				Type:    framework.TypeInt,
				Default: 3600,
				Description: `
Duration of the Impersonated Tokens
`,
			},
			"bindings": &framework.FieldSchema{
				Type:    framework.TypeString,
				Default: "{}",
				Description: `
	Bindings override to apply to CAB
	`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: withFieldValidator(b.pathCABWrite),
			logical.UpdateOperation: withFieldValidator(b.pathCABWrite),
			logical.DeleteOperation: withFieldValidator(b.pathCABDelete),
		},
	}
}

func (b *backend) pathCABWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var name string

	b.Logger().Debug(" Using Config %s ", name)
	configref := d.Get("config").(string)

	name = d.Get("name").(string)
	cab := &CABRules{}
	if v, ok := d.GetOk("bindings"); ok {
		if v.(string) == "" {
			return logical.ErrorResponse("bindings cannot be null"), logical.ErrInvalidRequest
		} else {
			s := v.(string)
			err := json.Unmarshal([]byte(s), &cab)
			if err != nil {
				return logical.ErrorResponse("Could Not parse CAB Bindings File"), logical.ErrInvalidRequest
			}
		}
	}

	localDuration := d.Get("duration").(int)

	k, err := b.CABKey(ctx, req.Storage, configref)
	if err != nil {
		if err == ErrKeyNotFound {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		return nil, err
	}

	if k.Restricted && len(cab.AccessBoundaryRules) > 0 {
		b.Logger().Debug(" Cannot set Boundary rules on Restricted Token")
		return logical.ErrorResponse("Cannot set Boundary rules on Restricted Token"), logical.ErrInvalidRequest
	}

	// config, err := b.Config(b.ctx, req.Storage)
	// if err != nil {
	// 	return nil, err
	// }

	projectID := k.Project
	b.Logger().Debug("pathCABWrite %v", projectID)

	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	creds, err := b.Credentials(req.Storage)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	var lifetime int
	if !k.Restricted {
		lifetime = localDuration
	} else {
		lifetime = k.Duration
	}
	if lifetime == 0 {
		lifetime = 3600
	}
	dlifetime := time.Duration(lifetime) * time.Second

	// TODO: delegates
	delegates := []string{}
	tokenSource, err := sal.ImpersonatedTokenSource(
		&sal.ImpersonatedTokenConfig{
			RootTokenSource: creds.TokenSource,
			TargetPrincipal: k.TargetServiceAccount,
			Lifetime:        dlifetime,
			Delegates:       delegates,
			TargetScopes:    k.Scopes,
		},
	)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	toki, err := tokenSource.Token()
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	b.Logger().Debug("Issued access_token %v ", toki.AccessToken)

	var salsrules []sal.AccessBoundaryRule
	var cabRules []CABRule

	if len(cab.AccessBoundaryRules) > 0 {
		cabRules = cab.AccessBoundaryRules
	} else {
		cabRules = k.Bindings.AccessBoundaryRules
	}

	for _, vals := range cabRules {

		rule := sal.AccessBoundaryRule{
			AvailableResource:    vals.AvailableResource,
			AvailablePermissions: vals.AvailablePermissions,
		}
		salsrules = append(salsrules, rule)
	}

	b.Logger().Debug("ACCESS BOUNDARY RULE %v ", salsrules)

	downScopedTokenSource, err := sal.DownScopedTokenSource(
		&sal.DownScopedTokenConfig{
			RootTokenSource:     tokenSource,
			AccessBoundaryRules: salsrules,
		},
	)
	tok, err := downScopedTokenSource.Token()
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	b.Logger().Debug("Issued access_token %v ", tok.AccessToken)

	return &logical.Response{
		Data: map[string]interface{}{
			"access_token": tok.AccessToken,
		},
	}, nil
}

func (b *backend) pathCABDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var name string

	name = d.Get("name").(string)
	// if v, ok := d.GetOk("cert_name"); ok {
	// 	name = v.(string)
	// } else {
	// 	return logical.ErrorResponse("CertificateName must be set"), logical.ErrInvalidRequest
	// }

	configref := d.Get("config").(string)
	k, err := b.CABKey(ctx, req.Storage, configref)
	if err != nil {
		if err == ErrKeyNotFound {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		return nil, err
	}

	projectID := k.Project

	b.Logger().Debug("Deleted CAB %s %v %v", name, configref, projectID)

	return &logical.Response{}, nil
}
