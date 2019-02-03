# Azure Key Vault Plugin
This plugin enables Jenkins to fetch secrets from Azure Keyvault and inject them directly into build jobs.
This works similarly to the [Credential Binding Plugin](https://wiki.jenkins-ci.org/display/JENKINS/Credentials+Binding+Plugin) and borrows much from the [Hashicorp Vault Plugin](https://wiki.jenkins-ci.org/display/JENKINS/HashiCorp+Vault+Plugin).
The plugin acts as an Azure Active Directory Application and must be configured with an Application ID and Token. Additional details [here](https://docs.microsoft.com/en-us/azure/app-service-mobile/app-service-mobile-how-to-configure-active-directory-authentication#optional-configure-a-native-client-application).

## System Configuration

### Via UI

In the Jenkins **Configure System** page, configure the following three options in the **Azure Key Vault Plugin** section
* **Key Vault URL** - The url where your keyvault resides (e.g. `https://myvault.vault.azure.net/`)
* **Credential ID** - The ID associated with a secret in the Jenkins secret store. Both **Microsoft Azure Service Principal** and **Username/Password** types are supported

### Via configuration as code

This plugin supports being configured with [configuration as code](https://github.com/jenkinsci/configuration-as-code-plugin/)
It requires both `configuration-as-code` and `configuration-as-code-support` plugins to be installed (support is required for credentials to be added)

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

You can also use a username / password credential:
```yaml
credentials:
  system:
    domainCredentials:
      - credentials:
        - usernamePassword:
            scope:    SYSTEM
            id:       "service-principal"
            username: client_id
            password: "${CLIENT_SECRET"
```


## Building the Plugin
* Run **mvn package**, an .hpi file will be generated in the target folder.

# Plugin Usage
### Usage in Jenkinsfile
Note that the example echos below will only show *****'s as the plugin redacts secrets found in the build log inside the
`withAzureKeyvault` build wrapper.


Simple version:
```groovy
node {
    def secrets = [
        [ secretType: 'Certificate', name: 'MyCert00', version: '', envVariable: 'CERTIFICATE' ],
        [ secretType: 'Secret', name: 'MySecret00', version: '', envVariable: 'SECRET' ]
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
    version: '',
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