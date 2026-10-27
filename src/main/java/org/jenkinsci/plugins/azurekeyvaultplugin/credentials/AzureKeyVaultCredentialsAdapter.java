package org.jenkinsci.plugins.azurekeyvaultplugin.credentials;

import com.cloudbees.plugins.credentials.common.IdCredentials;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.ExtensionList;
import hudson.ExtensionPoint;

/**
 * Turns an Azure Key Vault secret into a Jenkins credential.
 *
 * <p>The adapter is selected by the secret's {@code type} tag, see {@link #getType()}.
 * Other plugins can contribute adapters for their own credential types by registering an implementation
 * as an {@link hudson.Extension}.
 *
 * <p>Credentials should resolve their secret lazily through {@link AzureKeyVaultSecretContext#getSecret()},
 * and provide a {@link com.cloudbees.plugins.credentials.CredentialsSnapshotTaker} if they hold on to that
 * supplier, see {@link Snapshot}.
 */
public abstract class AzureKeyVaultCredentialsAdapter implements ExtensionPoint {

    /**
     * @return the value of the secret's {@code type} tag this adapter handles, e.g. {@code string}
     */
    @NonNull
    public abstract String getType();

    /**
     * @return the credential, or {@code null} to skip this secret (implementations should log why)
     */
    @CheckForNull
    public abstract IdCredentials adapt(@NonNull AzureKeyVaultSecretContext context) throws Exception;

    /**
     * @return the highest-ordinal adapter handling the given type, or {@code null} if there is none
     */
    @CheckForNull
    public static AzureKeyVaultCredentialsAdapter forType(@NonNull String type) {
        for (AzureKeyVaultCredentialsAdapter adapter : ExtensionList.lookup(AzureKeyVaultCredentialsAdapter.class)) {
            if (type.equals(adapter.getType())) {
                return adapter;
            }
        }
        return null;
    }
}
