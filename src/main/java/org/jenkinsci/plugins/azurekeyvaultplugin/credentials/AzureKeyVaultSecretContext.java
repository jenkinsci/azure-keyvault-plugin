package org.jenkinsci.plugins.azurekeyvaultplugin.credentials;

import com.cloudbees.plugins.credentials.CredentialsScope;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.util.Secret;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * A Key Vault secret being adapted to a credential by an {@link AzureKeyVaultCredentialsAdapter}.
 *
 * <p>The common tags ({@code jenkinsID}, {@code description}, {@code scope}) have already been resolved.
 */
public final class AzureKeyVaultSecretContext {

    private final CredentialsScope scope;
    private final String id;
    private final String description;
    private final String secretName;
    private final Map<String, String> tags;
    private final Supplier<Secret> secret;
    private final Function<String, Supplier<Secret>> secretLookup;

    public AzureKeyVaultSecretContext(
            @NonNull CredentialsScope scope,
            @NonNull String id,
            @NonNull String description,
            @NonNull String secretName,
            @NonNull Map<String, String> tags,
            @NonNull Supplier<Secret> secret,
            @NonNull Function<String, Supplier<Secret>> secretLookup
    ) {
        this.scope = scope;
        this.id = id;
        this.description = description;
        this.secretName = secretName;
        this.tags = tags;
        this.secret = secret;
        this.secretLookup = secretLookup;
    }

    @NonNull
    public CredentialsScope getScope() {
        return scope;
    }

    /**
     * @return the Jenkins credential ID, from the {@code jenkinsID} tag or else the secret name
     */
    @NonNull
    public String getId() {
        return id;
    }

    @NonNull
    public String getDescription() {
        return description;
    }

    /**
     * @return the name of the secret in the vault
     */
    @NonNull
    public String getSecretName() {
        return secretName;
    }

    @CheckForNull
    public String getTag(@NonNull String name) {
        return tags.get(name);
    }

    /**
     * @return a supplier that reads this secret's value from the vault on every {@link Supplier#get()}
     */
    @NonNull
    public Supplier<Secret> getSecret() {
        return secret;
    }

    /**
     * @param secretName the name of another secret in the same vault, e.g. from a {@code passphrase-id} tag
     * @return a supplier that reads that secret's value from the vault on every {@link Supplier#get()}
     */
    @NonNull
    public Supplier<Secret> getSecret(@NonNull String secretName) {
        return secretLookup.apply(secretName);
    }
}
