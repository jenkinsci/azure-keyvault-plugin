package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import hudson.ExtensionList;
import hudson.model.FreeStyleProject;
import hudson.security.ACL;
import java.util.List;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.RealJenkinsExtension;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;

/**
 * Boots a real Jenkins <em>without</em> the optional {@code cloudbees-folder} plugin and asserts that none of the
 * folder provider's extensions register, so credential lookups and item changes don't touch folder classes.
 *
 * <p>{@code @Extension(optional = true)} alone isn't enough: classes are resolved lazily, so an extension that
 * only references folder classes inside methods still registers and fails later, when it is used.
 */
class FoldersPluginIsolationTest {

    @RegisterExtension
    private final RealJenkinsExtension rjr = new RealJenkinsExtension().omitPlugins("cloudbees-folder");

    @Test
    void folderExtensionsAbsentWhenFoldersPluginAbsent() throws Throwable {
        rjr.then(FoldersPluginIsolationTest::assertFolderExtensionsAbsent);
    }

    private static void assertFolderExtensionsAbsent(JenkinsRule r) throws Exception {
        assertThat(ExtensionList.lookupSingleton(AzureCredentialsProvider.class), notNullValue());
        assertThat(extensionClassNames(CredentialsProvider.class), not(hasItem(FOLDER_PROVIDER)));
        assertThat(extensionClassNames(hudson.model.listeners.ItemListener.class), not(hasItem(FOLDER_PROVIDER + "$FolderListener")));

        FreeStyleProject project = r.createFreeStyleProject("job");
        project.renameTo("renamed");
        project.delete();
        assertThat(CredentialsProvider.lookupCredentialsInItem(StringCredentials.class, r.createFreeStyleProject("other"), ACL.SYSTEM2, List.of()), empty());
    }

    private static final String FOLDER_PROVIDER = "org.jenkinsci.plugins.azurekeyvaultplugin.provider.folder.FolderAzureCredentialsProvider";

    private static List<String> extensionClassNames(Class<?> type) {
        return ExtensionList.lookup(type).stream().map(e -> e.getClass().getName()).toList();
    }
}
