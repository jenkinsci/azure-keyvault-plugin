package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import hudson.util.Secret;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.githubapp.GitHubAppCredentialsFactory;
import org.jenkinsci.plugins.github_branch_source.GitHubAppCredentials;
import org.jenkinsci.plugins.github_branch_source.app_credentials.AccessSpecifiedRepositories;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertNull;

@WithJenkins
class AzureGitHubAppCredentialsTest {

    private static final String PEM = "-----BEGIN PRIVATE KEY-----\nMIIBVAIBADAN\n-----END PRIVATE KEY-----\n";

    private static Supplier<Secret> key() {
        // Secret.fromString needs a running Jenkins (ConfidentialStore), hence @WithJenkins.
        return () -> Secret.fromString(PEM);
    }

    private static Map<String, String> tags(String... kv) {
        Map<String, String> tags = new HashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            tags.put(kv[i], kv[i + 1]);
        }
        return tags;
    }

    @Test
    void mapsAllTagsToNativeGitHubAppCredentials(JenkinsRule j) {
        IdCredentials result = GitHubAppCredentialsFactory.create(
                CredentialsScope.GLOBAL,
                "my-app",
                "desc",
                tags("type", "githubApp", "appID", "123456", "owner", "my-org", "apiUri", "https://ghe.example.com/api/v3"),
                key());

        // Native type so github-branch-source's `instanceof GitHubAppCredentials` dispatch accepts it.
        assertThat(result, instanceOf(GitHubAppCredentials.class));
        GitHubAppCredentials cred = (GitHubAppCredentials) result;
        assertThat(cred.getId(), is("my-app"));
        assertThat(cred.getDescription(), is("desc"));
        assertThat(cred.getScope(), is(CredentialsScope.GLOBAL));
        assertThat(cred.getAppID(), is("123456"));
        assertThat(cred.getApiUri(), is("https://ghe.example.com/api/v3"));
        assertThat(cred.getPrivateKey().getPlainText(), is(PEM));
        // owner is exposed via the repository access strategy (getOwner() is deprecated and returns null)
        assertThat(cred.getRepositoryAccessStrategy(), instanceOf(AccessSpecifiedRepositories.class));
        assertThat(((AccessSpecifiedRepositories) cred.getRepositoryAccessStrategy()).getOwner(), is("my-org"));
    }

    @Test
    void ownerAndApiUriAreOptional(JenkinsRule j) {
        IdCredentials result = GitHubAppCredentialsFactory.create(
                CredentialsScope.GLOBAL, "app2", "", tags("type", "githubApp", "appID", "999"), key());

        assertThat(result, instanceOf(GitHubAppCredentials.class));
        GitHubAppCredentials cred = (GitHubAppCredentials) result;
        assertThat(cred.getAppID(), is("999"));
        assertThat(cred.getApiUri(), nullValue());
        // No owner tag -> no owner scoping applied
        assertThat(cred.getRepositoryAccessStrategy(), instanceOf(AccessSpecifiedRepositories.class));
        assertThat(((AccessSpecifiedRepositories) cred.getRepositoryAccessStrategy()).getOwner(), nullValue());
    }

    @Test
    void missingAppIdTagIsSkipped(JenkinsRule j) {
        assertNull(GitHubAppCredentialsFactory.create(
                CredentialsScope.GLOBAL, "app3", "", tags("type", "githubApp"), key()));
    }
}
