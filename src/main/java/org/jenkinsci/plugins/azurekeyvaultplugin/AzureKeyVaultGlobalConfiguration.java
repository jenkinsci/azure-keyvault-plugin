package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.microsoft.azure.util.AzureCredentials;
import com.microsoft.azure.util.AzureImdsCredentials;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.model.Item;
import hudson.security.ACL;
import hudson.util.ListBoxModel;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundSetter;

@Extension
@Symbol("azureKeyVault")
public class AzureKeyVaultGlobalConfiguration extends GlobalConfiguration {

    private String keyVaultURL;
    private String credentialID;

    public AzureKeyVaultGlobalConfiguration() {
        load();
    }

    public String getKeyVaultURL() {
        return keyVaultURL;
    }

    @DataBoundSetter
    public void setKeyVaultURL(String keyVaultURL) {
        this.keyVaultURL = keyVaultURL;
        save();
    }

    public String getCredentialID() {
        return credentialID;
    }

    @DataBoundSetter
    public void setCredentialID(String credentialID) {
        this.credentialID = credentialID;
        save();
    }

    @SuppressWarnings("unused")
    public ListBoxModel doFillCredentialIDItems(@AncestorInPath Item context) {
        if(context == null && !Jenkins.get().hasPermission(Jenkins.ADMINISTER) ||
                context != null && !context.hasPermission(Item.EXTENDED_READ)) {
            return new StandardListBoxModel();
        }

        return new StandardListBoxModel()
                .includeEmptyValue()
                .includeAs(ACL.SYSTEM, context, StandardUsernamePasswordCredentials.class)
                .includeAs(ACL.SYSTEM, context, AzureCredentials.class)
                .includeAs(ACL.SYSTEM, context, AzureImdsCredentials.class);
    }

    public static AzureKeyVaultGlobalConfiguration get() {
        return ExtensionList.lookupSingleton(AzureKeyVaultGlobalConfiguration.class);
    }
}
