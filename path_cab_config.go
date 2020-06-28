package gcpcab

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathCABConfigCRUD() *framework.Path {
	return &framework.Path{
		Pattern:      "cab/config/" + framework.GenericNameRegex("name"),
		HelpSynopsis: "Configure CAB root configuration policy",
		HelpDescription: `
see:  https://cloud.google.com/iam/docs/downscoping-short-lived-credentials
`,

		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `
Configuration Name.
`,
			},
			"project": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `
GCP ProjectID for the Impersonation and CAB
`,
			},
			"restricted": &framework.FieldSchema{
				Type:    framework.TypeBool,
				Default: true,
				Description: `
Is this CAB token restricted to the path parameters.
`,
			},
			"scopes": &framework.FieldSchema{
				Type:    framework.TypeCommaStringSlice,
				Default: []string{"https://www.googleapis.com/auth/cloud-platform"},
				Description: `
Scopes to apply to the Impersonated TOken
`,
			},
			"delegates": &framework.FieldSchema{
				Type:    framework.TypeCommaStringSlice,
				Default: []string{},
				Description: `
Delegates for Impersonation
`,
			},
			"duration": &framework.FieldSchema{
				Type:    framework.TypeInt,
				Default: 3600,
				Description: `
Duration of the Impersonated Token
`,
			},
			"bindings": &framework.FieldSchema{
				Type:    framework.TypeString,
				Default: "{}",
				Description: `
Bindings to apply to the CAB
	`,
			},

			"target_service_account": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `
Service Account to issue the CAB for
`,
			},

			"raw_token": &framework.FieldSchema{
				Type:    framework.TypeBool,
				Default: false,
				Description: `
Return raw access_token without CAB (i.,e just impersonation)
`,
			},
		},
		//		ExistenceCheck: b.pathKeysExistenceCheck,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   withFieldValidator(b.pathCABConfigRead),
			logical.UpdateOperation: withFieldValidator(b.pathCABConfigWrite),
			logical.DeleteOperation: withFieldValidator(b.pathCABConfigDelete),
		},
	}
}

// pathKeysConfigRead corresponds to GET cab/config/:name and is used to
// show information about the key configuration in Vault.
func (b *backend) pathCABConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	key := d.Get("name").(string)

	k, err := b.CABKey(ctx, req.Storage, "cab/config/"+key)
	if err != nil {
		if err == ErrKeyNotFound {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		return nil, err
	}

	data := map[string]interface{}{
		"target_service_account": k.TargetServiceAccount,
		"restricted":             k.Restricted,
		"scopes":                 k.Scopes,
		"duration":               k.Duration,
		"project":                k.Project,
		"bindings":               k.Bindings,
		"delegates":              k.Delegates,
		"raw_token":              k.RawToken,
	}

	return &logical.Response{
		Data: data,
	}, nil
}

// pathKeysConfigWrite corresponds to PUT/POST /generatekey/config/:name and
// configures information about the key in Vault.
func (b *backend) pathCABConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	key := d.Get("name").(string)
	k, err := b.CABKey(ctx, req.Storage, key)
	if err != nil {
		//return nil, err
		k = &ConfigSpec{}
	}

	if v, ok := d.GetOk("project"); ok {
		if v.(string) == "" {
			return logical.ErrorResponse("Project Config cannot be null"), logical.ErrInvalidRequest
		} else {
			k.Project = v.(string)
		}
	}

	if v, ok := d.GetOk("restricted"); ok {
		k.Restricted = v.(bool)
	}

	if v, ok := d.GetOk("scopes"); ok {
		k.Scopes = v.([]string)
	}
	if v, ok := d.GetOk("delegates"); ok {
		k.Delegates = v.([]string)
	}
	if v, ok := d.GetOk("duration"); ok {
		k.Duration = v.(int)
	}
	if v, ok := d.GetOk("target_service_account"); ok {
		if v.(string) == "" {
			return logical.ErrorResponse("target_service_account Config cannot be null"), logical.ErrInvalidRequest
		} else {
			k.TargetServiceAccount = v.(string)
		}
	}

	if v, ok := d.GetOk("bindings"); ok {
		if v.(string) == "" {
			return logical.ErrorResponse("bindings cannot be null"), logical.ErrInvalidRequest
		} else {
			var cab CABRules
			s := v.(string)
			err = json.Unmarshal([]byte(s), &cab)
			if err != nil {
				return logical.ErrorResponse("Could Not parse CAB Bindings File"), logical.ErrInvalidRequest
			}
			k.Bindings = cab
		}
	}

	if v, ok := d.GetOk("raw_token"); ok {
		k.RawToken = v.(bool)
	}

	if k.Restricted && k.RawToken {
		return logical.ErrorResponse("Cannot request raw_token for restricted key"), logical.ErrInvalidRequest
	}

	// Save it
	entry, err := logical.StorageEntryJSON("cab/config/"+key, k)
	if err != nil {
		return nil, errwrap.Wrapf("failed to create storage entry: {{err}}", err)
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, errwrap.Wrapf("failed to write to storage: {{err}}", err)
	}

	return nil, nil
}

func (b *backend) pathCABConfigDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	key := d.Get("name").(string)

	if err := req.Storage.Delete(ctx, "cab/config/"+key); err != nil {
		return nil, errwrap.Wrapf("failed to delete from storage: {{err}}", err)
	}
	return nil, nil

}
