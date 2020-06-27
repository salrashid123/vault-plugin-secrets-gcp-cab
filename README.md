
## Vault Secrets for GCP Credential Access Boundary and Impersonation

Vault plugin that exchanges a `VAULT_TOKEN` for a GCP `access_token` that as attenuated permissions.

The existing GCP `access_token` secrets plugin plugin Vault provides uses the credentials Vault is seeded with to create additional serviceAccounts "per roleset" and then assign them IAM permissions on GCP resources.  Essentially, its creating N service account and then applying permissions.  This technique has several limitations which is described [in the docs](https://www.vaultproject.io/docs/secrets/gcp#service-accounts-are-tied-to-rolesets).

In contrast, this plugin uses Vaults Service Account to perform [IAM Impersonation](https://cloud.google.com/iam/docs/creating-short-lived-service-account-credentials) on another Service Account and from there derive an `access_token`.  From there, the access_token that represents the target service account can be restricted further by applying [Credential Access Boundary](https://cloud.google.com/iam/docs/downscoping-short-lived-credentials) rules.

In other words, this plugin does not create new service accounts but rather assumes the identity of another service account and then attenuates the scope of GCP resources that new token can access.

There are two modes of operation:

1. Restricted Token
   In this mode, the VAULT admin defines a policy that stipulates the specific service account a Vault Policy can assume and the CAB resources they apply to.  A `VAULT_TOKEN` bearer cannot request extensions to include resources beyond what the admin defined

2. Unrestricted Token
   In this mode, the VAULT admin defines a policy that allows the `VAULT_TOKEN` bearer to  request a CAB with resources it wishes to access.  That is, the vault admin defines the service account to impersonate and leaves it upto the user to define the set of resources the `access_token` is valid against.  The user cannot ofcourse acquire a valid token capable of accessing any resource the impersonated credential doens't have access to anyway.

*Downscoped tokens only work with certain services like GCS*


>>> NOTE: this repository and plugin is NOT supported by Google

For more information on CAB and the libraries used here

- [Using Credential Access Boundary (DownScoped) Tokens](https://github.com/salrashid123/downscoped_token)
- [golang DownScopedTokenSource](https://github.com/salrashid123/oauth2#usage-downscoped)

### How it works..

Basically, the code uses Vaults Credentials to impersonate a service account and then downscope it as shown [here](https://gist.github.com/salrashid123/c894e3029be76243761709cf834c7ed1)

```golang
    defaultTokenSource, err := google.DefaultTokenSource(ctx, "https://www.googleapis.com/auth/iam")

    targetPrincipal := "impersonated-account@project.iam.gserviceaccount.com"
    lifetime := 30 * time.Second
    delegates := []string{}
    targetScopes := []string{"https://www.googleapis.com/auth/devstorage.read_only",
        "https://www.googleapis.com/auth/cloud-platform"}

    impersonatedTokenSource, err := sal.ImpersonatedTokenSource(
        &sal.ImpersonatedTokenConfig{
            RootTokenSource: defaultTokenSource,
            TargetPrincipal: targetPrincipal,
            Lifetime:        lifetime,
            Delegates:       delegates,
            TargetScopes:    targetScopes,
        },
    )

    downScopedTokenSource, err := sal.DownScopedTokenSource(
        &sal.DownScopedTokenConfig{
            RootTokenSource: impersonatedTokenSource,
            AccessBoundaryRules: []sal.AccessBoundaryRule{
                sal.AccessBoundaryRule{
                    AvailableResource: "//storage.googleapis.com/projects/_/buckets/" + bucketName,
                    AvailablePermissions: []string{
                        "inRole:roles/storage.objectViewer",
                    },
                },
            },
        },
    )
    // return token from the downScopedTokenSource()
```

### QuickStart

#### Setup

The following quick start uses Vault in `dev` mode.  You'll need 
- `golang1.14`
- `make`
- `Vault` 

First configure the two service accounts.

- `vault-server`:  This is the service account vault runs as
- `generic-server`: This is the service account vault can impersonate

Allow `vault-server` permission to impersonate `generic-server`

Create two GCS Buckets and allow `generic-server` permissions on both.


```bash

export PROJECT_ID=`gcloud config get-value core/project`
export PROJECT_NUMBER=`gcloud projects describe $PROJECT_ID --format="value(projectNumber)"`
export IMPERSONATED_SERVICE_ACCOUNT=generic-server@$PROJECT_ID.iam.gserviceaccount.com
export BUCKET_1=$PROJECT_ID-cab1
export BUCKET_2=$PROJECT_ID-cab2

gcloud iam service-accounts create vault-server --display-name "Vault Root Service Account"
gcloud iam service-accounts keys  create svc_account.json --iam-account=vault-server@$PROJECT_ID.iam.gserviceaccount.com

gcloud iam service-accounts create generic-server --display-name "Generic Service Account"

gsutil mb gs://$BUCKET_1
gsutil mb gs://$BUCKET_2

echo foo > file1.txt
gsutil cp file1.txt gs://$BUCKET_1/
gsutil cp file1.txt gs://$BUCKET_2/

gsutil uniformbucketlevelaccess set on gs://$BUCKET_1
gsutil uniformbucketlevelaccess set on gs://$BUCKET_2

gsutil iam ch serviceAccount:generic-server@$PROJECT_ID.iam.gserviceaccount.com:objectCreator,objectViewer gs://$BUCKET_1
gsutil iam ch serviceAccount:generic-server@$PROJECT_ID.iam.gserviceaccount.com:objectViewer gs://$BUCKET_2

gcloud iam service-accounts add-iam-policy-binding  generic-server@$PROJECT_ID.iam.gserviceaccount.com  --member=serviceAccount:vault-server@$PROJECT_ID.iam.gserviceaccount.com --role=roles/iam.serviceAccountTokenCreator

```

#### Configure Vault Policies

Configure the `.hcl` and CAB configuration files to use


`cab.json.tmpl` defines a rule that allows only access to one of the two buckets
`cab_override.json.tmpl` defines a rule that allows access to both buckets

```bash
envsubst < "cab.json.tmpl" > "cab.json"
envsubst < "cab_override.json.tmpl" > "cab_override.json"
envsubst < "tokenpolicy.hcl.tmpl" > "tokenpolicy.hcl"
```

#### Build

```bash
export VAULT_ADDR='http://localhost:8200'
export GOBIN=`pwd`/bin

rm bin/vault-plugin-secrets-gcp-cab
make fmt
make dev
```

#### RUN

```bash
export GOOGLE_APPLICATION_CREDENTIALS=`pwd`/svc_account.json

vault server -dev -dev-plugin-dir=./bin --log-level=debug
```

At this point, Vault is using the service account defined in `GOOGLE_APPLICATION_CREDENTIALS`

#### Install

In a new window, enable the plugin

For vault in `-dev` mode:

```bash
export VAULT_ADDR='http://localhost:8200'

export SHASUM=$(shasum -a 256 "bin/vault-plugin-secrets-gcp-cab" | cut -d " " -f1)

vault plugin register \
    -sha256="${SHASUM}" \
    -command="vault-plugin-secrets-gcp-cab" \
    secret gcpcab  

vault secrets enable -path="gcpcab" --plugin-name='vault-plugin-secrets-gcp-cab' plugin
```

#### Configure Policy


Then configure the policy.   Make sure the the environment variables are set
```bash
export PROJECT_ID=`gcloud config get-value core/project`
export PROJECT_NUMBER=`gcloud projects describe $PROJECT_ID --format="value(projectNumber)"`
export IMPERSONATED_SERVICE_ACCOUNT=generic-server@$PROJECT_ID.iam.gserviceaccount.com

vault write gcpcab/cab/config/myconfig  \
 project="$PROJECT_ID"  \
 target_service_account="$IMPERSONATED_SERVICE_ACCOUNT"  \
 scopes="https://www.googleapis.com/auth/cloud-platform"  \
 restricted=true \
 duration="3000" \
 bindings=@cab.json

vault write gcpcab/cab/config/myunrestrictedconfig \
  project="$PROJECT_ID" \
  target_service_account="$IMPERSONATED_SERVICE_ACCOUNT"  \
  scopes="https://www.googleapis.com/auth/cloud-platform" \
  duration="3000" \
  restricted=false 

vault policy write cert-policy tokenpolicy.hcl
vault token create -policy=cert-policy
```

This will result in a `VAULT_TOKEN` that is authorized for those paths

```
    Success! Uploaded policy: cert-policy
    Key                  Value
    ---                  -----
    token                s.ZLCMHwtDZiWsui8LaVQF8I7A
    token_accessor       treXG4U8cj2L4GUX2BFWWPSo
    token_duration       768h
    token_renewable      true
    token_policies       ["cert-policy" "default"]
    identity_policies    []
    policies             ["cert-policy" "default"]

```

The `token create` command will provide a `VAULT_TOKEN` that is restricted to the policy defined in `tokenpolicy.hcl`

#### Use VAULT_TOKEN (restricted)

In a new window, export the `VAULT_ADDR` and `VAULT_TOKEN`:

```bash
export VAULT_ADDR='http://localhost:8200'
export VAULT_TOKEN=<yourtoken>

export PROJECT_ID=`gcloud config get-value core/project`
export PROJECT_NUMBER=`gcloud projects describe $PROJECT_ID --format="value(projectNumber)"`
export IMPERSONATED_SERVICE_ACCOUNT=generic-server@$PROJECT_ID.iam.gserviceaccount.com
export BUCKET_1=$PROJECT_ID-cab1
export BUCKET_2=$PROJECT_ID-cab2
```

And attempt to get the new access token:

```bash
vault write gcpcab/cab/certname12020 config="myconfig"


Key             Value
---             -----
access_token    ya29.dr....
```

Now use that token to access GCS buckets:

```bash
export TOKEN=ya29.dr....


curl -s -H "Authorization: Bearer $TOKEN"  -o /dev/null  -w "%{http_code}\n" https://storage.googleapis.com/storage/v1/b/$BUCKET_1/o
curl -s -H "Authorization: Bearer $TOKEN"  -o /dev/null  -w "%{http_code}\n" https://storage.googleapis.com/storage/v1/b/$BUCKET_2/o

200
403
```

The CAB rule `cab.json` we defined allowed only access to `$BUCKET_1` so that explains the latter `403`


Now try to use the same `VAULT_TOKEN` to ask for your own user-defined bindings:

This won't work since our we never defined the policy to allow that path with those parameters
```

```bash
vault write gcpcab/cab/certname12020 \
    config="myconfig" bindings=@cab_override.json    

Error writing data to gcpcab/cab/certname12020: Error making API request.

URL: PUT http://localhost:8200/v1/gcpcab/cab/certname12020
Code: 403. Errors:

* 1 error occurred:
	* permission denied

```

Note the `allowed_parameters` do not include the `bindings=` flag:

```hcl
path "gcpcab/cab/certname12020" {
    capabilities = ["create", "update", "delete"]
    allowed_parameters = {    
      "config" = ["myconfig"]
  }
}
```

#### Use VAULT_TOKEN (unrestricted)

`tokenpolicy.hcl` also allowed that same token to create its own CAB definition.  This is allowed through the `reestricted=false` flag

```hcl
path "gcpcab/cab/config/myunrestrictedconfig" {
    capabilities = ["create", "update", "delete"]
    allowed_parameters = {
      "project" = ["$PROJECT_ID"] 
      "target_service_account" = ["$IMPERSONATED_SERVICE_ACCOUNT"]
      "duration" = ["3000"]
      "scopes" = ["https://www.googleapis.com/auth/cloud-platform"]
      "restricted" = [false]
  }
}

path "gcpcab/cab/certname22020" {
    capabilities = ["create", "update", "delete"]
    allowed_parameters = {    
      "config" = ["myunrestrictedconfig"]
      "duration" = [3000]
      "bindings" = []
  }
}

```
The corresponding CAB definition to do the override would be:  `cab_override.json`

```json
{
	"accessBoundaryRules" : [
	  {
		"availableResource" : "//storage.googleapis.com/projects/_/buckets/$BUCKET_1",
		"availablePermissions": ["inRole:roles/storage.objectViewer"]
      },
      {
		"availableResource" : "//storage.googleapis.com/projects/_/buckets/$BUCKET_2",
		"availablePermissions": ["inRole:roles/storage.objectViewer"]
	  }      
	]
}
```

So lets try to use that

```bash
vault write gcpcab/cab/certname22020  config="myunrestrictedconfig" \
  duration="3000"  bindings=@cab_override.json

Key             Value
---             -----
access_token    ya29.dr.ATVe...
```

```bash
curl -s -H "Authorization: Bearer $TOKEN"  -o /dev/null  -w "%{http_code}\n" https://storage.googleapis.com/storage/v1/b/$BUCKET_1/o
curl -s -H "Authorization: Bearer $TOKEN"  -o /dev/null  -w "%{http_code}\n" https://storage.googleapis.com/storage/v1/b/$BUCKET_2/o

200
200
```


The vault owner has set their own CAB config but one that is still restricted to the parent tokens' IAM capabilities


### Vault Plugin Registration for non-dev mode

If your Vault is running in non-dev mode and you uses our own Certs for TLS in `server.conf`:

```hcl
listener "tcp" {
  address = "vault.domain.com:8200"
  tls_cert_file = "/path/to/tls_crt_vault.pem"
  tls_key_file = "/path/to/tls_key_vault.pem"
}
api_addr = "https://vault.domain.com:8200"
plugin_directory = "/path/to/vault/plugins"
```

Then register the plugin and specify the the path to the TLS Certificate Vault server uses (`-args="-ca-cert=..."`):

```bash
export VAULT_CACERT=/path/to/tls_cacert.pem
vault plugin register \
    -sha256="${SHASUM}" \
    -command="vault-plugin-secrets-gcp-cab" \
    -args="-ca-cert=$VAULT_CACERT" secret gcpcab
```