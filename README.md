# Azure Key Vault Plugin

[![Build Status][jenkins-status]][jenkins-builds]
[![Jenkins Plugin][plugin-version-badge]][plugin]
[![GitHub release][github-release-badge]][github-release]
[![Jenkins Plugin Installs][plugin-install-badge]][plugin]

This plugin enables Jenkins to fetch secrets from Azure Key Vault and inject them directly into build jobs.
It works similarly to the [Credential Binding Plugin](https://plugins.jenkins.io/credentials-binding/) and borrows much from the [Hashicorp Vault Plugin](https://plugins.jenkins.io/hashicorp-vault-plugin/).
The plugin acts as an Azure Active Directory Application and must be configured with a valid credential.

## System Configuration

### Via UI

In the Jenkins **Configure System** page, configure the following two options in the **Azure Key Vault Plugin** section
* **Key Vault URL** - The url where your Key Vault resides (e.g. `https://myvault.vault.azure.net/`)
* **Credential ID** - The ID associated with a secret in the Jenkins secret store. Supported types are: 
    - **Azure Service Principal**
    - **Azure Managed Identity** (both user and system assigned)

### Via configuration-as-code

This plugin supports the [configuration as code](https://plugins.jenkins.io/configuration-as-code/) plugin:

Example yaml:
```yaml
credentials:
  system:
    domainCredentials:
      - credentials:
        - azure:
            azureEnvironmentName: "Azure"
            clientId: "d63d9de6-5f7a-48c1-ac1d-e90d4f5e5dcc"
            clientSecret: "${CLIENT_SECRET}"
            description: "An azure service principal"
            id: "service-principal"
            scope: SYSTEM
            subscriptionId: "d63d9de6-5f7a-48c1-ac1d-e90d4f5e5dcc"
            tenant: "d63d9de6-5f7a-48c1-ac1d-e90d4f5e5dcc"

unclassified:
  azureKeyVault:
    keyVaultURL: https://not-a-real-vault.vault.azure.net
    credentialID: service-principal
```

### Via system properties

URL:

```bash
-Djenkins.azure-keyvault.url=https://my.vault.azure.net
```

User or System Assigned Managed Identity:

```bash
-Djenkins.azure-keyvault.uami.enabled=true
```

Service principal:

```bash
-Djenkins.azure-keyvault.sp.client_id=...
-Djenkins.azure-keyvault.sp.client_secret=...
-Djenkins.azure-keyvault.sp.subscription_id=...
-Djenkins.azure-keyvault.sp.tenant_id=...
```

### Via environment variables

URL:

```bash
AZURE_KEYVAULT_URL=https://my.vault.azure.net
```

User or System Assigned Managed Identity:

```bash
AZURE_KEYVAULT_UAMI_ENABLED=true
```

Service principal:

```bash
AZURE_KEYVAULT_SP_CLIENT_ID=...
AZURE_KEYVAULT_SP_CLIENT_SECRET=...
AZURE_KEYVAULT_SP_SUBSCRIPTION_ID=...
AZURE_KEYVAULT_SP_TENANT_ID=...
```

## Passing a Secret File
It's possible to pass the secret from a file instead of passing the client secret as is.  Simply provide the path to the secret file.

```bash
-Djenkins.azure-keyvault.sp.client_id=...
-Djenkins.azure-keyvault.sp.client_secret_file=/path/to/secret/secretFile
-Djenkins.azure-keyvault.sp.subscription_id=...
-Djenkins.azure-keyvault.sp.tenant_id=...
```

```bash
AZURE_KEYVAULT_SP_CLIENT_ID=...
AZURE_KEYVAULT_SP_CLIENT_SECRET_FILE=/path/to/secret/secretFile
AZURE_KEYVAULT_SP_SUBSCRIPTION_ID=...
AZURE_KEYVAULT_SP_TENANT_ID=...
```

The plugin will parse the contents of the file as is.  The file should only contain the client_secret value.

## Building the Plugin
* Run **mvn package**, an .hpi file will be generated in the target folder.

## Plugin Usage
### Usage in Jenkinsfile
Note that the example echos below will only show *****'s as the plugin redacts secrets found in the build log inside the
`withAzureKeyvault` build wrapper.

#### Scripted
Snippet generator is fully supported for generating the possible values (along with inline help):
Go to any pipeline job and click `Pipeline Syntax`

Or visit the URL: `/job/<job-name>/pipeline-syntax/`

Simple version:
```groovy
node {
    def secrets = [
        [ secretType: 'Certificate', name: 'MyCert00', envVariable: 'CERTIFICATE' ],
        [ secretType: 'Secret', name: 'MySecret00', envVariable: 'SECRET' ],
        [ secretType: 'Secret', name: 'MySecret00', version: '342432lkjhdasjld', envVariable: 'SECRET' ]
    ]

    withAzureKeyvault(secrets) {
        sh 'echo $CERTIFICATE'
        sh 'echo $SECRET'
    }
}

```

With overrides:
```groovy
static LinkedHashMap<String, Object> secret(String secretName, String envVar) {
  [ 
    secretType: 'Secret',
    name: secretName,
    version: '342432lkjhdasjld',
    envVariable: envVar
  ]
}

node {
    def secrets = [
        secret('my-secret', 'MY_SECRET')
    ]

    withAzureKeyvault(
            azureKeyVaultSecrets: secrets, 
            keyVaultURLOverride: 'https://mykeyvault.vault.azure.net',
            credentialIDOverride: 'service-principal'
    ) {
        sh 'echo $MY_SECRET'
     }
}
```

#### Declarative
Snippet generator is fully supported for generating the possible values (along with inline help):
Go to any pipeline job and click `Pipeline Syntax` -> `Declarative Directive Generator`

Or visit the URL: `/job/<job-name>/directive-generator/`


Simple:
```groovy
pipeline {
    agent any
    stages {
        stage('Build') {
            options {
              azureKeyVault([[envVariable: 'MY_SECRET', name: 'my-secret', secretType: 'Secret']])
            }
            steps {
                sh "echo $SECRET"
            }
        }
    }
}
```

With overrides:
```groovy
pipeline {
    agent any
    stages {
        stage('Build') {
            options {
              azureKeyVault(
                credentialID: 'my-sp', 
                keyVaultURL: 'https://my.vault.azure.net', 
                secrets: [
                    [envVariable: 'MY_SECRET', name: 'my-secret', secretType: 'Secret']
                ]
              )
            }
            steps {
                sh "echo $SECRET"
            }
        }
    }
}
```

Certificate:
```groovy
pipeline {
    agent any
    stages {
        stage('Build') {
            options {
              azureKeyVault([[envVariable: 'CERT_LOCATION', name: 'my-cert-name', secretType: 'Certificate']])
            }
            steps {
                sh "openssl pkcs12 -in $CERT_LOCATION  -nodes -password 'pass:' -out keyvault.pem"
            }
        }
    }
}
```

The shell command above will convert the PFX file to a pem key file (also containing the certificate), note that Azure Key Vault removes the password
on the pfx when you import it, if you're importing it back into Azure somewhere else you may need to convert it to pem and convert back to a pfx with a password.

### Azure Key Vault Credentials Provider

> Note: It is not supported to configure the credential provider with the Configuration as Code plugin *and* resolving credentials from Azure Key Vault in the same configuration file. Please use one of the other options (system properties, environment variables) if you want to retrieve secrets for use in Configuration as Code files

This plugin enables the retrieval of Secrets directly from Azure Key Vault.
After the configuration is set up, secrets from the key vault can be viewed in the credentials page like this:

![provider](./docs/image/provider.png)

*Note* These credentials are read-only and metadata caching(10 minutes) means newly created secrets may not be here immediately.
You can reload the cache on the system configuration page if you need a new secret to appear.

Use these credentials just as other normal credentials in Jenkins.

There are multiple supported credential types, `string` is used by default.
To use a different type add a tag called `type` with one of the below values:

- `string` - Secret text
- `username` - Username with password
  - add a tag `username` for the username of the credential
- `sshUserPrivateKey` - SSH Private key
  - add a tag `username` for the username of the credential
  - (optional) add a tag `username-is-secret` and set it to true to hide the username in the build logs 

Declarative Pipeline:

```groovy
pipeline {
    agent any
    environment {
        GITHUB_API_TOKEN = credentials('github-api-token')
    }
    stages {
        stage('Foo') {
            steps {
                echo '$GITHUB_API_TOKEN'
            }
        }
    }
}
```

Scripted Pipeline:

```groovy
node {
    withCredentials([string(credentialsId: 'github-api-token', variable: 'GITHUB_API_TOKEN')]) {
        echo '$GITHUB_API_TOKEN'
    }
}
```

#### Username with password

```bash
az keyvault secret set --vault-name my-vault \
  --name github-pat \
  --value my-pat \
  --tags username=github-user type=username
```

Scripted Pipeline:  
```groovy
job('my example') {
    scm {
        git {
            remote {
                github('my-repo', 'https')
                credentials('github-pat')
            }
        }
    }
}
```

#### SSH Username with private key

```bash
az keyvault secret set --tags type=sshUserPrivateKey username=my-username \
  --vault-name my-vault \
  --name test-ssh \
  -f ~/.ssh/my-ssh-key
```

Scripted pipeline:

```bash
# This is a docker image that can be used to test out this feature
docker run --rm -it --publish 2222:2222 \
  -e "PUBLIC_KEY=my-public-key" linuxserver/openssh-server
```

```groovy
node {
    withCredentials([sshUserPrivateKey(credentialsId: "test-ssh", keyFileVariable: "my_ssh_key", usernameVariable: "my_username")]) {
     sh 'ssh -i $my_ssh_key -p 2222 $my_username@localhost "uname -r"'
    }
}
```

Declarative pipeline:

```groovy
pipeline {
    agent any
    environment {
        SSH_PRIVATE_KEY = credentials('test-ssh')
    }
    stages {
        stage('Foo') {
            steps {
                sh 'ssh -i $SSH_PRIVATE_KEY -p 2222 $SSH_PRIVATE_KEY_USR@localhost "cat world"'
            }
        }
    }
}
```

#### SSH Username with private key and passphrase

If your SSH private keys has a passphrase you need to add a tag `passphrase-id` which references the secret that the passphrase is stored in.


Create the passphrase secret:

```bash
az keyvault secret set \
  --vault-name my-vault \
  --name test-ssh-passphrase \
  --value my-ssh-passphrase
```
With the secret now in your vault, when creating a secret of type `sshUserPrivateKey`, specify the passphrase using a tag `passphrase-id` set with the **name** of the passphrase secret you created.

```bash
az keyvault secret set --tags type=sshUserPrivateKey username=my-username passphrase-id=test-ssh-passphrase \
  --vault-name my-vault \
  --name test-ssh \
  -f ~/.ssh/my-ssh-key
```

Creating the sshUserPrivateKey will query the AKV once again for the passphrase value.  If the passphrase could not be found in the vault, the passphrase value will be defaulted to Null.

#### Secret Labels

The Azure Key Vault Plugin provides the ability to filter which secrets are set via the Azure Key Vault Credentials Provider Plugin.  By default, the plugin will load all secrets stored within the Key Vault.  However, your Key Vault may be the Secret Source for multiple applications, or contains system information for your deployment environment not needed directly by Jenkins.  To filter out secrets from being set, add a System Property or Environment Variable:

**Via System Property**:

```bash
-Djenkins.azure-keyvault.label_selector=myCustomLabel
```

**Via Environment Variable**:
```bash
AZURE_KEYVAULT_LABEL_SELECTOR=myCustomLabel
```

If included in your config, when the Azure Key Vault plugin is resolving credentials from your Key Vault, it will skip any secret that does not contain a tag `label=myCustomLabel`.  For example, if two secrets are set within the KeyVault:

```bash
az keyvault secret set --vault-name my-vault \
  --name testUserNoLabel \
  --value example1 \
  --tags username=testUserNoLabel type=username
```

```bash
az keyvault secret set --vault-name my-vault \
  --name testUserWithLabel \
  --value example2 \
  --tags username=testUserWithLabel type=username label=myCustomLabel
```

With the System Property or Environment variable being set in this example, only the usernamePassword `testUserWithLabel` will be present in your Jenkins instance.

### SecretSource

The plugin allows the [Configuration as Code plugin](https://plugins.jenkins.io/configuration-as-code) to interpolate string secrets from Azure KeyVault.

#### Example

az cli:

```bash
az keyvault secret set --vault-name my-vault --name my-password --value password
```

JCasC:

```yaml
jenkins:
  securityRealm:
    local:
      allowsSignup: false
      users:
      - id: "foo"
        password: "${my-password}"
```

[jenkins-builds]: https://ci.jenkins.io/job/Plugins/job/azure-keyvault-plugin/job/master/
[jenkins-status]: https://ci.jenkins.io/buildStatus/icon?job=Plugins/azure-keyvault-plugin/master
[plugin-version-badge]: https://img.shields.io/jenkins/plugin/v/azure-keyvault.svg
[plugin-install-badge]: https://img.shields.io/jenkins/plugin/i/azure-keyvault.svg?color=blue
[plugin]: https://plugins.jenkins.io/azure-keyvault
[github-release-badge]: https://img.shields.io/github/release/jenkinsci/azure-keyvault-plugin.svg?label=release
[github-release]: https://github.com/jenkinsci/azure-keyvault-plugin/releases/latest
