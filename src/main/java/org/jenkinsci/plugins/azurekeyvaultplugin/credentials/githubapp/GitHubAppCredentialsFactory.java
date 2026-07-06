package org.jenkinsci.plugins.azurekeyvaultplugin.credentials.githubapp;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import hudson.util.Secret;
import java.util.Collections;
import java.util.Map;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.plugins.github_branch_source.GitHubAppCredentials;
import org.jenkinsci.plugins.github_branch_source.app_credentials.AccessSpecifiedRepositories;

/**
 * Builds {@link GitHubAppCredentials} from an Azure Key Vault secret's tags.
 *
 * <p>All references to the optional {@code github-branch-source} plugin are isolated in this class.
 * {@code AzureCredentialsProvider} must not import or reference {@link GitHubAppCredentials} directly:
 * doing so makes the whole provider fail to load (a verification-time {@code NoClassDefFoundError})
 * when that optional plugin is absent, which would break every credential type, not just this one.
 * Callers must confirm the plugin is installed before invoking {@link #create}; that call is what
 * first loads this class (and therefore the {@code github-branch-source} classes it references).
 */
public final class GitHubAppCredentialsFactory {

    private static final Logger LOG = Logger.getLogger(GitHubAppCredentialsFactory.class.getName());

    private GitHubAppCredentialsFactory() {
    }

    /**
     * @param privateKey supplier of the GitHub App private key (PKCS#8 PEM); resolved eagerly because
     *                   {@link GitHubAppCredentials} reads its key field directly during token
     *                   generation and cannot resolve it lazily.
     * @return the credential (as an {@link IdCredentials} so callers need no compile-time reference to
     *         {@code github-branch-source}), or {@code null} if the required {@code appID} tag is blank.
     */
    public static IdCredentials create(
            CredentialsScope scope, String jenkinsID, String description,
            Map<String, String> tags, Supplier<Secret> privateKey) {
        String appId = tags.get("appID");
        if (StringUtils.isBlank(appId)) {
            LOG.log(Level.WARNING, "Skipping GitHub App credential {0}: missing required 'appID' tag", jenkinsID);
            return null;
        }
        GitHubAppCredentials cred = new GitHubAppCredentials(scope, jenkinsID, description, appId, privateKey.get());
        String owner = tags.get("owner");
        if (StringUtils.isNotBlank(owner)) {
            // Scope the app to a single owner. Equivalent to the deprecated setOwner(owner) but without
            // triggering the CasC MigrationAdminMonitor on every cache refresh. Empty repository list
            // means "all repositories the app can access for this owner".
            cred.setRepositoryAccessStrategy(new AccessSpecifiedRepositories(owner, Collections.emptyList()));
        }
        String apiUri = tags.get("apiUri");
        if (StringUtils.isNotBlank(apiUri)) {
            cred.setApiUri(apiUri);
        }
        return cred;
    }
}
