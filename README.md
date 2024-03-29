
## Vault Secrets for GCP Credential Access Boundary and Impersonation

Vault plugin that exchanges a `VAULT_TOKEN` for a GCP `access_token` that as attenuated permissions.

The existing GCP `access_token` secrets plugin plugin Vault provides uses the credentials Vault is seeded with to create additional serviceAccounts "per roleset" and then assign them IAM permissions on GCP resources.  Essentially, its creating N service account and then applying permissions.  This technique has several limitations which is described [in the docs](https://www.vaultproject.io/docs/secrets/gcp#service-accounts-are-tied-to-rolesets).

In contrast, this plugin uses Vaults Service Account to perform [IAM Impersonation](https://cloud.google.com/iam/docs/creating-short-lived-service-account-credentials) on another Service Account and get its `access_token`.  From there, the `access_token` that represents the target service account can be restricted further by applying [Credential Access Boundary](https://cloud.google.com/iam/docs/downscoping-short-lived-credentials) rules.

In other words, this plugin does not create new service accounts but rather assumes the identity of another service account and then attenuates the scope of GCP resources that new token can access.

>> NOTE: since this plugin uses service account impersonation, the target account(s) to impersonate must already exist.

There are two modes of operation:

1. `Restricted Token`
   In this mode, the VAULT admin defines a policy that stipulates the specific service account a client can assume and the CAB resources it apply to.  
   A `VAULT_TOKEN` bearer cannot request extensions to include resources beyond what the admin defined for the CAB

   * vault admin defines restricted policy on resourceA
   * client -> vault_server 
   * vault_server return CAB token 
   * client uses CAB token to access resourceA

2. `Unrestricted Token`
   In this mode, the VAULT admin defines a policy that allows the `VAULT_TOKEN` bearer to get an `access_token` that represents the impersonated account but the token is not attenuated.
   This mode is essentially impersonation _except_ that the vault admin can define basic settings like lifetime, delegation and scopes for the impersonated token.

   * vault admin defines unrestricted policy to impersonate serviceAccountA
   * client requests an access_token from vault_server but stipulates a policy to resourceA
   * vault_server return downscoped token 
   * client uses token to access resourceA


   the difference between 1 and 2 is that the admin defines the CAB restricts but in 2, the client requests the CAB restrict for a predefined service account that the admin assigned by policy.

 2. `Impersonation`
   In this mode, the VAULT admin defines a policy that allows the `VAULT_TOKEN` bearer to get an `access_token` that represents the impersonated account but the token is not attenuated.
   This mode is service account impersonation without scope or lifetime overrides an admin may have set as would be the case with an unrestricted token 

*Downscoped tokens only work with certain services like GCS*


>>> NOTE: this repository and plugin is NOT supported by Google


### How it works..

Basically, the code uses Vaults Credentials to impersonate a service account and then downscope 

```golang
import (
	"golang.org/x/oauth2/google/downscope"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

    targetPrincipal := "impersonated-account@project.iam.gserviceaccount.com"
    lifetime := 30 * time.Second
    delegates := []string{}
    targetScopes := []string{"https://www.googleapis.com/auth/cloud-platform"}

    creds, _ := google.FindDefaultCredentials(ctx, cloudPlatformScope)

    // first impersonate the target service account
    impersonatedTokenSource, _err_ := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
      TargetPrincipal: targetPrincipal,
      Scopes:          targetScopes,
      Lifetime:        lifetime,
      Delegates:       delegates,
    }, option.WithCredentials(creds))

    // then downscope that impersonated account
    accessBoundary := []downscope.AccessBoundaryRule{
      {
        AvailableResource:    "//storage.googleapis.com/projects/_/buckets/" + bucketName,
        AvailablePermissions: []string{"inRole:roles/storage.objectViewer"},
        Condition: &downscope.AvailabilityCondition{
          Expression: expression,
        },
      },
    }

    downScopedTokenSource, _ := downscope.NewTokenSource(ctx, downscope.DownscopingConfig{RootSource: impersonatedTokenSource, Rules: accessBoundary})

    // return token from the downScopedTokenSource()
```

### QuickStart

#### Setup

The following quick start uses Vault in `dev` mode.  You'll need 
- `golang1.16+`
- `make`
- `Vault v1.8.1` 

First configure the two service accounts.

- `vault-server`:  This is the service account vault runs as
- `impersonated-account`: This is the service account vault can impersonate

Allow `vault-server` permission to impersonate `impersonated-account`

Create two GCS Buckets and allow `generic-server` permissions on both.

Allow vault's service account to impersonate `IMPERSONATED_SERVICE_ACCOUNT`

```bash
export PROJECT_ID=`gcloud config get-value core/project`
export PROJECT_NUMBER=`gcloud projects describe $PROJECT_ID --format="value(projectNumber)"`
export BUCKET_1=$PROJECT_ID-cab1
export BUCKET_2=$PROJECT_ID-cab2

gcloud iam service-accounts create vault-server --display-name "Vault Root Service Account"
gcloud iam service-accounts keys  create svc_account.json --iam-account=vault-server@$PROJECT_ID.iam.gserviceaccount.com
export VAULT_SERVICE_ACCOUNT=vault-server@$PROJECT_ID.iam.gserviceaccount.com

gcloud iam service-accounts create impersonated-account --display-name "Impersonated Service Account"
export IMPERSONATED_SERVICE_ACCOUNT=impersonated-account@$PROJECT_ID.iam.gserviceaccount.com

echo $VAULT_SERVICE_ACCOUNT
echo $IMPERSONATED_SERVICE_ACCOUNT
echo $BUCKET_1
echo $BUCKET_2

gsutil mb gs://$BUCKET_1
gsutil mb gs://$BUCKET_2

echo foo1 > file1.txt
echo foo2 > file2.txt
gsutil cp file1.txt gs://$BUCKET_1/
gsutil cp file2.txt gs://$BUCKET_2/

gsutil uniformbucketlevelaccess set on gs://$BUCKET_1
gsutil uniformbucketlevelaccess set on gs://$BUCKET_2

gsutil iam ch serviceAccount:$IMPERSONATED_SERVICE_ACCOUNT:objectCreator,objectViewer gs://$BUCKET_1
gsutil iam ch serviceAccount:$IMPERSONATED_SERVICE_ACCOUNT:objectViewer gs://$BUCKET_2

# allow Vault service account to impersonate 
gcloud iam service-accounts add-iam-policy-binding  $IMPERSONATED_SERVICE_ACCOUNT \
 --member=serviceAccount:$VAULT_SERVICE_ACCOUNT --role=roles/iam.serviceAccountTokenCreator
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
# set the VAULT_TOKEN if -dev  switch is not used for vault server
# export VAULT_TOKEN=

export SHASUM=$(shasum -a 256 "bin/vault-plugin-secrets-gcp-cab" | cut -d " " -f1)

vault plugin register \
    -sha256="${SHASUM}" \
    -command="vault-plugin-secrets-gcp-cab" \
    secret gcpcab  

vault secrets enable -path="gcpcab" --plugin-name='vault-plugin-secrets-gcp-cab' plugin
```

#### Configure Policy


Then configure the policy you are interested in.   Make sure the the environment variables are set.

The following will configure both a restricted and unrestricted policy:

```bash
# create restricted token

vault write gcpcab/cab/config/myconfig  \
 project="$PROJECT_ID"  \
 target_service_account="$IMPERSONATED_SERVICE_ACCOUNT"  \
 scopes="https://www.googleapis.com/auth/cloud-platform"  \
 restricted=true \
 duration="3000" \
 bindings=@cab.json

vault policy write restricted-policy -<<EOF
path "gcpcab/cab/certname12020" {
    capabilities = ["update", "delete"]
    allowed_parameters = {    
      "config" = ["myconfig"]
  }
}
EOF

vault token create -policy=restricted-policy


## now create an unrestricted token

vault write gcpcab/cab/config/myunrestrictedconfig \
  project="$PROJECT_ID" \
  target_service_account="$IMPERSONATED_SERVICE_ACCOUNT"  \
  scopes="https://www.googleapis.com/auth/cloud-platform" \
  duration="3000" \
  restricted=false 

vault policy write unrestricted-policy -<<EOF
path "gcpcab/cab/certname22020" {
    capabilities = ["update", "delete"]
    allowed_parameters = {    
      "config" = ["myunrestrictedconfig"]
      "duration" = ["3000"]
      "bindings" = []
  }
}
EOF

vault token create -policy=unrestricted-policy
```

#### Restricted TOKEN

In a new window, export the `VAULT_ADDR` and `VAULT_TOKEN` that was associated with the restricted policy:

```bash
export VAULT_ADDR='http://localhost:8200'
export VAULT_TOKEN=<yourtoken>

export PROJECT_ID=`gcloud config get-value core/project`
export PROJECT_NUMBER=`gcloud projects describe $PROJECT_ID --format="value(projectNumber)"`
export IMPERSONATED_SERVICE_ACCOUNT=impersonated-account@$PROJECT_ID.iam.gserviceaccount.com
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

curl -s -H "Authorization: Bearer $TOKEN"  -o /dev/null  -w "%{http_code}\n" https://storage.googleapis.com/storage/v1/b/$BUCKET_1/o/file1.txt
curl -s -H "Authorization: Bearer $TOKEN"  -o /dev/null  -w "%{http_code}\n" https://storage.googleapis.com/storage/v1/b/$BUCKET_2/o/file2.txt

200
403
```

The CAB rule `cab.json` we defined allowed only access to `$BUCKET_1` so that explains the latter `403`


#### Unrestricted TOKEN

The unrestricted policy was originally set with `reestricted=false` flag which means a `VAULT_TOKEN` that uses it
can define the CAB rule _but not the service account being impersonated_

Use the corresponding CAB definition to do the override:  `cab_override.json` which allows read access to both buckets

```json
{
"accessBoundaryRules" : [
	  {
      "availableResource" : "//storage.googleapis.com/projects/_/buckets/$BUCKET_1",
      "availablePermissions": ["inRole:roles/storage.objectViewer"],
      "availabilityCondition" : {
          "title" : "obj-exact",
          "expression" : "resource.name == \"projects/_/buckets/$BUCKET_1/objects/file1.txt\""
      }	      
    },
    {
      "availableResource" : "//storage.googleapis.com/projects/_/buckets/$BUCKET_2",
      "availablePermissions": ["inRole:roles/storage.objectViewer"],
      "availabilityCondition" : {
          "title" : "obj-exact",
          "expression" : "resource.name == \"projects/_/buckets/$BUCKET_2/objects/file2.txt\""
       }       
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
curl -s -H "Authorization: Bearer $TOKEN"  -o /dev/null  -w "%{http_code}\n" https://storage.googleapis.com/storage/v1/b/$BUCKET_1/o/file1.txt
curl -s -H "Authorization: Bearer $TOKEN"  -o /dev/null  -w "%{http_code}\n" https://storage.googleapis.com/storage/v1/b/$BUCKET_2/o/file2.txt

200
200
```
Since the derived CAB config the user set allows for both bucket read, you'll see `200` responses

### Impersonated Token

You can also optionally request a completely unrestricted token.  That is, you can apply a policy to return the non attenuated token for `IMPERSONATED_SERVICE_ACCOUNT`.

To do this, specify `restricted=false` and `raw_token=true` in the policy config:

```bash
vault write gcpcab/cab/config/mytotallyunrestrictedconfig  \
 project="$PROJECT_ID"  \
 target_service_account="$IMPERSONATED_SERVICE_ACCOUNT"  \
 scopes="https://www.googleapis.com/auth/cloud-platform"  \
 restricted=false \
 raw_token=true

vault policy write impersonated-policy -<<EOF
path "gcpcab/cab/certname62020" {
    capabilities = ["update", "delete"]
    allowed_parameters = {    
      "config" = ["mytotallyunrestrictedconfig"]
  }
}
EOF

vault token create -policy=impersonated-policy

vault write gcpcab/cab/certname62020 config="mytotallyunrestrictedconfig"
```

### Vault Plugin Registration for non-dev mode

If your Vault is running in non-dev mode and you uses our own Certs for TLS in `server.conf` on host `vault.domain.com`:

- `server.conf`

```hcl
backend "file" {
  path = "/path/to/filebackend"
}

ui = true

listener "tcp" {
  address = "vault.domain.com:8200"
  tls_cert_file = "/path/to/crt_vault.pem"
  tls_key_file = "/path/to/key_vault.pem"
}

api_addr = "https://vault.domain.com:8200"

plugin_directory = "/path/to/plugins"
```

(you can find the sample certs [here](https://gist.github.com/salrashid123/2506b1ae74db9c803a7dae2653bc20ee)).  If you wan to test this locally, edit `/etc/hosts` and set `127.0.0.1 vault.domain.com`

- vault started with 

  `vault server --config server.conf`

- compile and install plugin

```bash
cd vault-plugin-secrets-gcp-cab
mkdir -p bin
export GOBIN=`pwd`/bin

rm bin/vault-plugin-secrets-gcp-cab
make fmt
make dev

export SHASUM=$(shasum -a 256 "bin/vault-plugin-secrets-gcp-cab" | cut -d " " -f1)
echo $SHASUM 


cp bin/vault-plugin-secrets-gcp-cab /apps/vault/plugins
```

- now register the plugin 

```bash
# assume this is the root token
export VAULT_TOKEN=...
export VAULT_SERVER=https://vault.domain.com:8200
export VAULT_CACERT=/apps/vault/CA_crt.pem

vault plugin register \
    -sha256="${SHASUM}" \
    -command="vault-plugin-secrets-gcp-cab" \
    -args="-ca-cert=$VAULT_CACERT" gcpcab

vault secrets enable -path="gcpcab" --plugin-name='gcpcab' plugin
```

### Specify credentials per mount

By default, the plugin will use `Application Default Credentials` to access GCP CA.  If you need different credentials per mount, you can specify that using the `config/` path of the mount point.  For example, to specify a credential file JSON certificate for the `/gcpcab` mount:

```
vault write gcpcab/config \
  credentials=@/path/to/svc_account.json
```
