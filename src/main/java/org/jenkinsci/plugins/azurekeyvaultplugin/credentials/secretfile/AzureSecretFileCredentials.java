package org.jenkinsci.plugins.azurekeyvaultplugin.credentials.secretfile;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.util.Secret;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.function.Supplier;
import org.jenkinsci.plugins.azurekeyvaultplugin.AzureCredentialsProvider;
import org.jenkinsci.plugins.plaincredentials.FileCredentials;
import org.jenkinsci.plugins.plaincredentials.impl.Messages;
import org.jvnet.localizer.ResourceBundleHolder;

public class AzureSecretFileCredentials extends BaseStandardCredentials implements FileCredentials {

    @NonNull
    private final String fileName;

    @NonNull
    private final Supplier<Secret> secretBytes;

    public AzureSecretFileCredentials(
        CredentialsScope scope,
        String id,
        String description,
        String fileName,
        Supplier<Secret> secretBytes
    ) {
        super(scope, id, description);
        this.fileName = fileName;
        this.secretBytes = secretBytes;
    }

    @NonNull
    @Override
    public String getFileName() {
        return fileName;
    }

    @NonNull
    @Override
    public InputStream getContent() throws java.io.UnsupportedEncodingException {
        String fileContent = Secret.toString(getSecretBytes());
        return new ByteArrayInputStream(fileContent.getBytes("UTF-8"));
    }

    public Secret getSecretBytes() {
        return secretBytes.get();
    }

    @Extension
    @SuppressWarnings("unused")
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {
        @Override
        @NonNull
        public String getDisplayName() {
            return ResourceBundleHolder.get(Messages.class).format("FileCredentialsImpl.secret_file");
        }

        @Override
        public boolean isApplicable(CredentialsProvider provider) {
            return provider instanceof AzureCredentialsProvider;
        }
    }
}
