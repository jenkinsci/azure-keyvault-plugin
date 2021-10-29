package org.jenkinsci.plugins.azurekeyvaultplugin.credentials.usernamepassword;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.cloudbees.plugins.credentials.impl.Messages;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.Util;
import hudson.util.Secret;
import java.util.function.Supplier;
import org.jenkinsci.plugins.azurekeyvaultplugin.provider.CredentialsProviderHelper;
import org.jvnet.localizer.ResourceBundleHolder;


public class AzureUsernamePasswordCredentials extends BaseStandardCredentials implements StandardUsernamePasswordCredentials {
    private final Supplier<Secret> password;
    private final String username;

    public AzureUsernamePasswordCredentials(
            String id,
            String username,
            String description,
            Supplier<Secret> password
    ) {
        super(id, description);
        this.password = password;
        this.username = Util.fixNull(username);
    }

    @NonNull
    @Override
    public Secret getPassword() {
        return password.get();
    }

    @NonNull
    @Override
    public String getUsername() {
        return this.username;
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

        @Override
        public boolean isApplicable(CredentialsProvider provider) {
            return CredentialsProviderHelper.isAzureCredentialsProvider(provider);
        }
    }
}
