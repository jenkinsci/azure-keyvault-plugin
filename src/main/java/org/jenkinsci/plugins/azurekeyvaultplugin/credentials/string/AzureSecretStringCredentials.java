package org.jenkinsci.plugins.azurekeyvaultplugin.credentials.string;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.util.Secret;
import java.util.function.Supplier;
import org.jenkinsci.plugins.azurekeyvaultplugin.AzureCredentialsProvider;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.jenkinsci.plugins.plaincredentials.impl.Messages;
import org.jvnet.localizer.ResourceBundleHolder;

public class AzureSecretStringCredentials extends BaseStandardCredentials implements StringCredentials {

    private final Supplier<Secret> value;

    public AzureSecretStringCredentials(String id, String description, Supplier<Secret> value) {
        super(id, description);
        this.value = value;
    }

    @NonNull
    @Override
    public Secret getSecret() {
        return value.get();
    }

    @Extension
    @SuppressWarnings("unused")
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {
        @Override
        @NonNull
        public String getDisplayName() {
            return ResourceBundleHolder.get(Messages.class).format("StringCredentialsImpl.secret_text");
        }

        @Override
        public boolean isApplicable(CredentialsProvider provider) {
            return provider instanceof AzureCredentialsProvider;
        }
    }
}
