# azure-keyvault-plugin
The Jenkins plugin for Azure Key Vault enable Jenkins to fetch secrets from Azure Keyvault and inject them directly into build jobs.
This works similarly to the [Credential Binding Plugin](https://wiki.jenkins-ci.org/display/JENKINS/Credentials+Binding+Plugin) and borrows much from the [Hashicorp Vault Plugin](https://wiki.jenkins-ci.org/display/JENKINS/HashiCorp+Vault+Plugin).
The plugin acts as an Azure Active Directory Application and must be configured with an Application ID and Token. Additional details [here](https://docs.microsoft.com/en-us/azure/app-service-mobile/app-service-mobile-how-to-configure-active-directory-authentication#optional-configure-a-native-client-application).

## System Configuration
In the Jenkins **Configure System** page, configure the following three options in the **Azure Key Vault Plugin** section
* **Key Vault URL** - The url where your keyvault resides (e.g. `**https://myvault.vault.azure.net/**`)
* **Application ID** - An application ID that is permitted to access the serets in your keyvault. ([More details](https://docs.microsoft.com/en-us/azure/app-service-mobile/app-service-mobile-how-to-configure-active-directory-authentication#optional-configure-a-native-client-application))
* **Application Secret** - A secret/token that is associated with your Azure AD application.

## Job Configuration
In each build job that will use the plugin, configure the following in the **Azure Key Vault Plugin** section
* **Secret Type** - There are two options - Secrets (AKA passwords) and Certificates.
* **Name** - The name Key Vault uses to store this password.
* **Version** - The version of the secret to retrieve from Key Vault.
* **Environment Variable** - The variable to which the secret will be bound, so it can be used in your build steps.
  * For **Secrets**, the variable will hold the value of the secret
  * For **Certificates**, the variable will hold the path to the certificate file on disk
* _(Optional)_ Override the **Key Vault URL, Application ID, or Application Secret**. This is useful if different vaults are used by different jobs.

