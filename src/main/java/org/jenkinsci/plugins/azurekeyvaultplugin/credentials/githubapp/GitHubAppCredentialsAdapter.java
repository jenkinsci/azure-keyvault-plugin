package org.jenkinsci.plugins.azurekeyvaultplugin.credentials.githubapp;

import com.cloudbees.plugins.credentials.common.IdCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.AzureKeyVaultCredentialsAdapter;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.AzureKeyVaultSecretContext;
import org.jenkinsci.plugins.github_branch_source.GitHubAppCredentials;
import org.jenkinsci.plugins.github_branch_source.app_credentials.AccessSpecifiedRepositories;
import org.jenkinsci.plugins.variant.OptionalExtension;

/**
 * Builds {@link GitHubAppCredentials} from an Azure Key Vault secret's tags.
 *
 * <p>Only registered when the optional {@code github-branch-source} plugin is installed. All references to
 * that plugin are isolated in this class, so other classes must not reference {@link GitHubAppCredentials}.
 */
@OptionalExtension(requirePlugins = "github-branch-source")
@SuppressWarnings("unused")
public class GitHubAppCredentialsAdapter extends AzureKeyVaultCredentialsAdapter {

    private static final Logger LOG = Logger.getLogger(GitHubAppCredentialsAdapter.class.getName());

    @NonNull
    @Override
    public String getType() {
        return "githubApp";
    }

    /**
     * The private key (PKCS#8 PEM) is resolved eagerly because {@link GitHubAppCredentials} reads its key
     * field directly during token generation and cannot resolve it lazily.
     *
     * @return the credential, or {@code null} if the required {@code appID} tag is blank.
     */
    @Override
    public IdCredentials adapt(@NonNull AzureKeyVaultSecretContext context) {
        String appId = context.getTag("appID");
        if (StringUtils.isBlank(appId)) {
            LOG.log(Level.WARNING, "Skipping GitHub App credential {0}: missing required 'appID' tag", context.getId());
            return null;
        }
        GitHubAppCredentials cred = new GitHubAppCredentials(
                context.getScope(), context.getId(), context.getDescription(), appId, context.getSecret().get()
        );
        String owner = context.getTag("owner");
        if (StringUtils.isNotBlank(owner)) {
            // Scope the app to a single owner. Equivalent to the deprecated setOwner(owner) but without
            // triggering the CasC MigrationAdminMonitor on every cache refresh. Empty repository list
            // means "all repositories the app can access for this owner".
            cred.setRepositoryAccessStrategy(new AccessSpecifiedRepositories(owner, Collections.emptyList()));
        }
        String apiUri = context.getTag("apiUri");
        if (StringUtils.isNotBlank(apiUri)) {
            cred.setApiUri(apiUri);
        }
        return cred;
    }
}
