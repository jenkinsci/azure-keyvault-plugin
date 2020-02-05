package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Suppliers;
import com.microsoft.azure.PagedList;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import com.microsoft.azure.keyvault.models.CertificateItem;
import com.microsoft.azure.keyvault.models.SecretItem;
import com.microsoft.jenkins.keyvault.SecretCertificateCredentials;
import com.microsoft.jenkins.keyvault.SecretStringCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.model.ItemGroup;
import hudson.model.ModelObject;
import hudson.security.ACL;
import hudson.util.Secret;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import okhttp3.OkHttpClient;
import org.acegisecurity.Authentication;
import org.apache.commons.lang3.StringUtils;


@Extension
public class AzureCredentialsProvider extends CredentialsProvider {
    private static final Logger LOG = Logger.getLogger(AzureCredentialsProvider.class.getName());

    private final AzureCredentialsStore store = new AzureCredentialsStore(this);

    private final Supplier<Collection<IdCredentials>> credentialsSupplier =
            memoizeWithExpiration(AzureCredentialsProvider::fetchCredentials, Duration.ofMinutes(5));

    private static <T> Supplier<T> memoizeWithExpiration(Supplier<T> base, Duration duration) {
        return Suppliers.memoizeWithExpiration(base::get, duration.toMillis(), TimeUnit.MILLISECONDS)::get;
    }

    @NonNull
    @Override
    public <C extends Credentials> List<C> getCredentials(@NonNull Class<C> aClass, @Nullable ItemGroup itemGroup,
                                                          @Nullable Authentication authentication) {
        Logger.getLogger(OkHttpClient.class.getName()).setLevel(Level.FINE);
        if (ACL.SYSTEM.equals(authentication)) {
            final ArrayList<C> list = new ArrayList<>();
            for (IdCredentials credential : credentialsSupplier.get()) {
                if (aClass.isAssignableFrom(credential.getClass())) {
                    // cast to keep generics happy even though we are assignable..
                    list.add(aClass.cast(credential));
                }
                LOG.log(Level.FINEST, "getCredentials {0} does not match", credential.getId());
            }
            return list;
        }

        return Collections.emptyList();
    }

    @VisibleForTesting
    static String generateKeyvaultItemName(String itemId) {
        if (StringUtils.isEmpty(itemId)) {
            throw new AzureKeyVaultException("Empty id for key vault item.");
        }
        int count = 0;
        int index = -1;
        for (int i = itemId.length() - 1; i >= 0; i--) {
            if (itemId.charAt(i) == '/') {
                count++;
            }
            if (count == 2) {
                index = i;
                break;
            }
        }
        if (index < 0) {
            throw new AzureKeyVaultException("Wrong pattern for key vault item id.");
        }
        return itemId.substring(index + 1);
    }

    private static Collection<IdCredentials> fetchCredentials() {
        AzureKeyVaultGlobalConfiguration azureKeyVaultGlobalConfiguration = GlobalConfiguration.all().get(AzureKeyVaultGlobalConfiguration.class);
        if (azureKeyVaultGlobalConfiguration == null) {
            throw new AzureKeyVaultException("No global key vault url configured.");
        }

        String credentialID = azureKeyVaultGlobalConfiguration.getCredentialID();
        KeyVaultCredentials keyVaultCredentials = AzureKeyVaultCredentialRetriever.getCredentialById(credentialID);
        KeyVaultClient client = new KeyVaultClient(keyVaultCredentials);
        String keyVaultURL = azureKeyVaultGlobalConfiguration.getKeyVaultURL();
        List<IdCredentials> credentials = new ArrayList<>();
        PagedList<SecretItem> secretItems = client.getSecrets(keyVaultURL);
        for (SecretItem secretItem : secretItems) {
            String id = secretItem.id();
            IdCredentials cred = new SecretStringCredentials(CredentialsScope.GLOBAL, generateKeyvaultItemName(id),
                    id, credentialID,
                    secretItem.id());
            credentials.add(cred);
        }
        PagedList<CertificateItem> certificateItems = client.getCertificates(keyVaultURL);
        for (CertificateItem certificateItem : certificateItems) {
            String id = certificateItem.id();
            IdCredentials cred = new SecretCertificateCredentials(CredentialsScope.GLOBAL, generateKeyvaultItemName(id), id,
                    credentialID,
                    certificateItem.id(), Secret.decrypt(""));
            credentials.add(cred);
        }
        client.httpClient().connectionPool().evictAll();
        return credentials;
    }

    @Override
    public CredentialsStore getStore(ModelObject object) {
        return object == Jenkins.get() ? store : null;
    }

    @Override
    public String getIconClassName() {
        return "icon-azure-key-vault-credentials-store";
    }
}
