package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.impl.Messages;
import com.microsoft.jenkins.keyvault.BaseSecretCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.Util;
import hudson.util.Secret;
import org.jvnet.localizer.ResourceBundleHolder;


public class AzureKeyVaultUsernamePasswordCredentials extends BaseSecretCredentials implements StandardUsernamePasswordCredentials {
    final protected CredentialsScope scope;
    final protected String username;


    public AzureKeyVaultUsernamePasswordCredentials(
            CredentialsScope scope,
            String id,
            String username,
            String description,
            String servicePrincipalId,
            String secretIdentifier) {
        super(scope, id, description, servicePrincipalId, secretIdentifier);
        this.scope = scope;
        this.username = Util.fixNull(username);
    }

    @NonNull
    @Override
    public Secret getPassword() {
        final KeyVaultSecret secretBundle = getKeyVaultSecret();
        return Secret.fromString(secretBundle.getValue());
    }

    @NonNull
    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public CredentialsScope getScope() {
        return this.scope;
    }

    @Extension(ordinal = 1)
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public String getDisplayName() {
            return ResourceBundleHolder.get(Messages.class).format("UsernamePasswordCredentialsImpl.DisplayName");
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getIconClassName() {
            return "icon-credentials-userpass";
        }
    }
}
