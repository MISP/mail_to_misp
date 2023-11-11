# O365MISPClient

A mail_to_misp client to connect your O365 mail infrastructure to [MISP](https://github.com/MISP/MISP) in order to create events based on the information contained within emails.


## Getting Started
### OAuth Setup (Pre Requisite)
You will need to register your application at [Microsoft Apps](https://apps.dev.microsoft.com/). Steps below:

1. Login to https://apps.dev.microsoft.com/
2. Create an app, note your app id (**client_id**)
3. Generate a new password (**client_secret**) under **Application Secrets** section 
4. Under the **Platform** section, add a new Web platform and set "https://outlook.office365.com/owa/" as the redirect URL
5. Under **Microsoft Graph Permissions** section, Add the below delegated permission (or based on what scopes you plan to use)
   1. offline_access
   2. Mail.Read
   3. Mail.Read.Shared
6. Note the **client_id** and **client_secret** as they will be using for establishing the connection through the api

Detailed documentation for getting [Oauth Authentication](https://github.com/O365/python-o365/blob/master/README.md#oauth-authentication) configured.

## Token Storage
When authenticating you will retrieve oauth tokens. If you don't want a one time access you will have to store the token somewhere. O365 makes no assumptions on where to store the token and tries to abstract this from the library usage point of view.

You can choose where and how to store tokens by using the proper Token Backend.

**Take care: the access (and refresh) token must remain protected from unauthorized users.**

To store the token you will have to provide a properly configured TokenBackend.


### FileSystemTokenBackend
(Default backend): Stores and retrieves tokens from the file system. Tokens are stored as files. You can explicitly initialize this as shown below.
```python
from O365.utils import FileSystemTokenBackend


# initialize Mail2MISP
m2m = Mail2MISP(misp_url, misp_key, misp_verifycert, config=config)

tb = FileSystemTokenBackend(token_path='/path/to/store/token', token_filename='o365_token.txt')

# initialize O365MISPClient
o365 = m2m.O365MISPClient(
        client_id=o365_client_id,
        client_secret=o365_client_secret,
        tenant_id=o365_tenant_id,
        resource=o365_resource,
        scopes=o365_scopes,
        token_backend=tb
)
```

As this is the default backend, you do not need to explicitly initialize FileSystemTokenBackend. If ```token_backend``` is ```None``` the token file will be saved as ```o365_token.txt``` to the directory the script is running in.

```python
# initialize Mail2MISP
m2m = Mail2MISP(misp_url, misp_key, misp_verifycert, config=config)

# initialize O365MISPClient
o365 = m2m.O365MISPClient(
        client_id=o365_client_id,
        client_secret=o365_client_secret,
        tenant_id=o365_tenant_id,
        resource=o365_resource,
        scopes=o365_scopes,
        token_backend=None
)
```

### AWSSecretsBackend
Stores and retrieves tokens from an AWS Secrets Management vault.
```python
from O365.utils import AWSSecretsBackend


# initialize Mail2MISP
m2m = Mail2MISP(misp_url, misp_key, misp_verifycert, config=config)

tb = AWSSecretsBackend(secret_name='o365_m2m_token', region_name='us-east-1')

# initialize O365MISPClient
o365 = m2m.O365MISPClient(
        client_id=o365_client_id,
        client_secret=o365_client_secret,
        tenant_id=o365_tenant_id,
        resource=o365_resource,
        scopes=o365_scopes,
        token_backend=tb
)
```

### EnvTokenBackend
Stores and retrieves tokens from environment variables.
```python
from O365.utils import EnvTokenBackend


# initialize Mail2MISP
m2m = Mail2MISP(misp_url, misp_key, misp_verifycert, config=config)

tb = EnvTokenBackend('O365_M2M_TOKEN')

# initialize O365MISPClient
o365 = m2m.O365MISPClient(
        client_id=o365_client_id,
        client_secret=o365_client_secret,
        tenant_id=o365_tenant_id,
        resource=o365_resource,
        scopes=o365_scopes,
        token_backend=tb
)
```