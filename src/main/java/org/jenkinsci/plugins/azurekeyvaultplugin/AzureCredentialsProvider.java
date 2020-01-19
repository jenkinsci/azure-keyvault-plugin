package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.google.common.base.Suppliers;
import com.microsoft.azure.PagedList;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.models.CertificateBundle;
import com.microsoft.azure.keyvault.models.CertificateItem;
import com.microsoft.azure.keyvault.models.SecretBundle;
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
import org.acegisecurity.Authentication;


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

    private static Collection<IdCredentials> fetchCredentials() {
        AzureKeyVaultGlobalConfiguration azureKeyVaultGlobalConfiguration = GlobalConfiguration.all().get(AzureKeyVaultGlobalConfiguration.class);
        if (azureKeyVaultGlobalConfiguration == null) {
            throw new AzureKeyVaultException("No global key vault url configured.");
        }
        KeyVaultClient client = new KeyVaultClient(new AzureKeyVaultImdsCredential());
        String keyVaultURL = azureKeyVaultGlobalConfiguration.getKeyVaultURL();
        List<IdCredentials> credentials = new ArrayList<>();
        PagedList<SecretItem> secretItems = client.getSecrets(keyVaultURL);
        for (SecretItem secretItem : secretItems) {
                SecretBundle secret = client.getSecret(secretItem.id());
                IdCredentials cred = new SecretStringCredentials(CredentialsScope.GLOBAL, secretItem.id(), "", secret.id(),
                        secret.secretIdentifier().identifier());
                credentials.add(cred);
        }
        PagedList<CertificateItem> certificateItems = client.getCertificates(keyVaultURL);
        for (CertificateItem certificateItem : certificateItems) {
            CertificateBundle certificate = client.getCertificate(certificateItem.id());
            IdCredentials cred = new SecretCertificateCredentials(CredentialsScope.GLOBAL, certificateItem.id(), "",
                    certificate.id(),
                    certificate.secretIdentifier().identifier(), Secret.decrypt(""));
            credentials.add(cred);
        }
        return credentials;
    }

    @Override
    public CredentialsStore getStore(ModelObject object) {
        return object == Jenkins.getInstance() ? store : null;
    }

    @Override
    public String getIconClassName() {
        return "icon-azure-key-vault-credentials-store";
    }
}
