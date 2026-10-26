package org.jenkinsci.plugins.azurekeyvaultplugin.provider.folder;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.microsoft.azure.util.AzureBaseCredentials;
import com.microsoft.azure.util.AzureImdsCredentials;
import hudson.model.FreeStyleProject;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.model.User;
import hudson.security.ACL;
import hudson.util.Secret;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.azurekeyvaultplugin.credentials.string.AzureSecretStringCredentials;
import org.jenkinsci.plugins.azurekeyvaultplugin.provider.folder.FolderAzureCredentialsProvider.FolderAzureKeyVaultCredentialsProperty;
import org.jenkinsci.plugins.azurekeyvaultplugin.provider.folder.FolderAzureCredentialsProvider.VaultKey;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

@WithJenkins
class FolderAzureCredentialsProviderTest {

    private static final String PARENT_VAULT = "https://parent.vault.azure.net/";
    private static final String CHILD_VAULT = "https://child.vault.azure.net/";
    private static final String AZURE_CREDENTIAL_ID = "azure-sp";

    private final Map<String, Map<String, IdCredentials>> vaults = new HashMap<>();
    private final AtomicInteger loads = new AtomicInteger();
    private Function<VaultKey, Map<String, IdCredentials>> originalLoader;

    @BeforeEach
    void setUp() {
        originalLoader = FolderAzureCredentialsProvider.loader;
        FolderAzureCredentialsProvider.loader = key -> {
            loads.incrementAndGet();
            return vaults.getOrDefault(key.keyVaultURL(), Collections.emptyMap());
        };
        vault(PARENT_VAULT,
                secret(CredentialsScope.GLOBAL, "shared", "from-parent"),
                secret(CredentialsScope.GLOBAL, "parent-only", "parent-value"),
                secret(CredentialsScope.SYSTEM, "system-scoped", "should-not-be-visible"));
        vault(CHILD_VAULT,
                secret(CredentialsScope.GLOBAL, "shared", "from-child"));
    }

    @AfterEach
    void tearDown() {
        FolderAzureCredentialsProvider.loader = originalLoader;
    }

    @Test
    void itemsSeeCredentialsOfTheirFolderAndParentFolders(JenkinsRule j) throws Exception {
        Folder parent = folderWithVault(j.jenkins, "parent", PARENT_VAULT);
        Folder child = parent.createProject(Folder.class, "child");
        child.addProperty(new FolderAzureKeyVaultCredentialsProperty(CHILD_VAULT, AZURE_CREDENTIAL_ID));
        FreeStyleProject inChild = child.createProject(FreeStyleProject.class, "job");
        FreeStyleProject inParent = parent.createProject(FreeStyleProject.class, "job");
        FreeStyleProject atRoot = j.createFreeStyleProject("job");

        assertThat(secretOf(inChild, "shared"), is("from-child"));
        assertThat(secretOf(inChild, "parent-only"), is("parent-value"));
        assertThat(secretOf(inParent, "shared"), is("from-parent"));
        assertThat(secretOf(atRoot, "shared"), nullValue());

        assertThat(idsVisibleTo(inChild), containsInAnyOrder("shared", "parent-only"));
        assertThat(idsVisibleTo(atRoot), empty());
    }

    @Test
    void systemScopedSecretsAreIgnored(JenkinsRule j) throws Exception {
        Folder folder = folderWithVault(j.jenkins, "folder", PARENT_VAULT);
        FreeStyleProject job = folder.createProject(FreeStyleProject.class, "job");

        assertThat(secretOf(job, "system-scoped"), nullValue());
        assertThat(secretOf(folder, "system-scoped"), nullValue());
        assertThat(storeOf(folder).getCredentials(Domain.global()).stream().map(c -> ((IdCredentials) c).getId()).toList(),
                containsInAnyOrder("shared", "parent-only"));
    }

    @Test
    void azureCredentialsAreNeverLookedUpInTheVault(JenkinsRule j) throws Exception {
        Folder folder = folderWithVault(j.jenkins, "folder", PARENT_VAULT);

        // the provider resolves these to connect to the vault, answering would recurse into the cache
        FolderAzureCredentialsProvider provider = FolderAzureCredentialsProvider.get();
        assertThat(provider.getCredentialsInItem(AzureBaseCredentials.class, folder, ACL.SYSTEM2, List.of()), empty());
        assertThat(provider.getCredentialByIdInItem(AZURE_CREDENTIAL_ID, AzureBaseCredentials.class, folder, ACL.SYSTEM2, List.of()), nullValue());
        assertThat(loads.get(), is(0));
    }

    @Test
    void storeIsReadOnlyAndOnlyOnConfiguredFolders(JenkinsRule j) throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        j.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.ADMINISTER).everywhere().to("admin"));
        Folder configured = folderWithVault(j.jenkins, "configured", PARENT_VAULT);
        Folder plain = j.jenkins.createProject(Folder.class, "plain");
        FolderAzureCredentialsProvider provider = FolderAzureCredentialsProvider.get();

        assertThat(provider.getStore(plain), nullValue());
        CredentialsStore store = provider.getStore(configured);
        assertThat(store, notNullValue());
        var admin = User.getById("admin", true).impersonate2();
        assertThat(store.hasPermission2(admin, CredentialsProvider.VIEW), is(true));
        assertThat(store.hasPermission2(admin, CredentialsProvider.CREATE), is(false));
        assertThat(store.hasPermission2(admin, CredentialsProvider.UPDATE), is(false));
        assertThat(store.hasPermission2(admin, CredentialsProvider.DELETE), is(false));
    }

    @Test
    void configRoundTrip(JenkinsRule j) throws Exception {
        Folder folder = folderWithVault(j.jenkins, "folder", PARENT_VAULT);

        j.configRoundtrip(folder);

        FolderAzureKeyVaultCredentialsProperty property = folder.getProperties().get(FolderAzureKeyVaultCredentialsProperty.class);
        assertThat(property.getKeyVaultURL(), is(PARENT_VAULT));
        assertThat(property.getCredentialID(), is(AZURE_CREDENTIAL_ID));
        assertThat(property.getStore(), notNullValue());
    }

    @Test
    void storeSurvivesReload(JenkinsRule j) throws Exception {
        folderWithVault(j.jenkins, "folder", PARENT_VAULT);

        j.jenkins.reload();

        Folder folder = j.jenkins.getItemByFullName("folder", Folder.class);
        assertThat(FolderAzureCredentialsProvider.get().getStore(folder), notNullValue());
    }

    @Test
    void reconfiguringAFolderRefreshesItsCredentials(JenkinsRule j) throws Exception {
        Folder folder = folderWithVault(j.jenkins, "folder", PARENT_VAULT);
        FreeStyleProject job = folder.createProject(FreeStyleProject.class, "job");
        assertThat(secretOf(job, "shared"), is("from-parent"));
        int loadsBefore = loads.get();

        j.configRoundtrip(folder);

        assertThat(secretOf(job, "shared"), is("from-parent"));
        assertThat(loads.get(), is(loadsBefore + 1));
    }

    @Test
    void pipelineCanBindFolderCredential(JenkinsRule j) throws Exception {
        Folder folder = folderWithVault(j.jenkins, "folder", PARENT_VAULT);
        WorkflowJob job = folder.createProject(WorkflowJob.class, "pipeline");
        job.setDefinition(new CpsFlowDefinition("""
                node {
                    withCredentials([string(credentialsId: 'parent-only', variable: 'SECRET')]) {
                        echo "length ${SECRET.length()}"
                    }
                }""", true));

        WorkflowRun run = j.buildAndAssertSuccess(job);

        j.assertLogContains("length " + "parent-value".length(), run);
    }

    private static Folder folderWithVault(Jenkins jenkins, String name, String keyVaultURL) throws Exception {
        SystemCredentialsProvider system = SystemCredentialsProvider.getInstance();
        if (system.getCredentials().isEmpty()) {
            // only needs to exist so the credential select in the folder configuration keeps its value
            system.getCredentials().add(new AzureImdsCredentials(CredentialsScope.GLOBAL, AZURE_CREDENTIAL_ID, ""));
            system.save();
        }
        Folder folder = jenkins.createProject(Folder.class, name);
        folder.addProperty(new FolderAzureKeyVaultCredentialsProperty(keyVaultURL, AZURE_CREDENTIAL_ID));
        return folder;
    }

    private static CredentialsStore storeOf(Folder folder) {
        return FolderAzureCredentialsProvider.get().getStore(folder);
    }

    private static String secretOf(Item item, String id) {
        StringCredentials credentials = CredentialsProvider.lookupCredentialsInItem(StringCredentials.class, item, ACL.SYSTEM2, List.of())
                .stream()
                .filter(c -> c.getId().equals(id))
                .findFirst()
                .orElse(null);
        StringCredentials byId = item instanceof ItemGroup<?> group
                ? FolderAzureCredentialsProvider.get().getCredentialByIdInItemGroup(id, StringCredentials.class, group, ACL.SYSTEM2, List.of())
                : FolderAzureCredentialsProvider.get().getCredentialByIdInItem(id, StringCredentials.class, item, ACL.SYSTEM2, List.of());
        String viaList = credentials == null ? null : credentials.getSecret().getPlainText();
        String viaId = byId == null ? null : byId.getSecret().getPlainText();
        assertThat("lookup by id and by listing should agree for " + id, viaId, is(viaList));
        return viaId;
    }

    private static List<String> idsVisibleTo(Item item) {
        return FolderAzureCredentialsProvider.get()
                .getCredentialsInItem(Credentials.class, item, ACL.SYSTEM2, List.of())
                .stream()
                .map(c -> {
                    assertThat(c, instanceOf(IdCredentials.class));
                    return ((IdCredentials) c).getId();
                })
                .toList();
    }

    private void vault(String url, IdCredentials... credentials) {
        Map<String, IdCredentials> map = new HashMap<>();
        for (IdCredentials credential : credentials) {
            map.put(credential.getId(), credential);
        }
        vaults.put(url, map);
    }

    private static IdCredentials secret(CredentialsScope scope, String id, String value) {
        return new AzureSecretStringCredentials(scope, id, "", () -> Secret.fromString(value));
    }
}
