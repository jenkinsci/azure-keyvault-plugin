package org.jenkinsci.plugins.azurekeyvaultplugin.credentials.sshuserprivatekey;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.util.Secret;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.azurekeyvaultplugin.AzureCredentialsProvider;
import org.jenkinsci.plugins.plaincredentials.impl.Messages;
import org.jvnet.localizer.ResourceBundleHolder;

public class AzureSSHUserPrivateKeyCredentials extends BaseStandardCredentials implements SSHUserPrivateKey {

    private final String username;
    private final boolean usernameSecret;
    private final Supplier<Secret> value;

    public AzureSSHUserPrivateKeyCredentials(
            String id,
            String description,
            String username,
            boolean usernameSecret,
            Supplier<Secret> privateKey
    ) {
        super(id, description);
        this.username = username;
        this.usernameSecret = usernameSecret;
        this.value = privateKey;
    }

    public Secret getSecretValue() {
        return value.get();
    }

    @NonNull
    @Override
    public String getPrivateKey() {
        String key = Secret.toString(value.get());

        return appendNewLineIfMissing(key);
    }

    @Override
    public Secret getPassphrase() {
        return null;
    }

    @NonNull
    @Override
    public List<String> getPrivateKeys() {
        String privateKeys = Secret.toString(value.get());
        List<String> keys = StringUtils.isBlank(privateKeys) ? Collections.emptyList() : Arrays.asList(StringUtils.split(privateKeys, "\f"));

        return keys.stream()
                .map(AzureSSHUserPrivateKeyCredentials::appendNewLineIfMissing)
                .collect(Collectors.toList());
    }

    private static String appendNewLineIfMissing(String key) {
        return key.endsWith("\n") ? key : key + "\n";
    }

    @NonNull
    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isUsernameSecret() {
        return usernameSecret;
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
