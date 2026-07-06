package org.jenkinsci.plugins.azurekeyvaultplugin;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;

/**
 * Guards the optional-dependency boundary for {@code github-branch-source}.
 *
 * <p>{@code GitHubAppCredentials} comes from an <em>optional</em> plugin. If any always-loaded class
 * (e.g. the {@code @Extension} {@link AzureCredentialsProvider}) carries a compile-time reference to a
 * {@code github_branch_source} type, the JVM loads that type while verifying the referencing class, so
 * the whole class fails to load with {@code NoClassDefFoundError} when the plugin is absent — taking
 * every credential type down with it. No ordinary test catches this, because the test JVM always has
 * the plugin on its classpath. This static check does: every reference must be confined to the
 * {@code credentials.githubapp} package, which is only loaded after a runtime plugin-presence check.
 *
 * <p>Note: the package path is {@code github_branch_source} (underscores); the plugin id used in
 * {@code getPlugin("github-branch-source")} uses hyphens, so that legitimate call is not flagged.
 */
class OptionalPluginIsolationTest {

    private static final String OPTIONAL_PLUGIN_PACKAGE = "github_branch_source";

    /** The one package allowed to reference the optional plugin (loaded only past the presence guard). */
    private static final String ISOLATION_PACKAGE =
            "org/jenkinsci/plugins/azurekeyvaultplugin/credentials/githubapp/";

    @Test
    void noAlwaysLoadedClassReferencesTheOptionalPlugin() throws Exception {
        Path classesRoot = Paths.get(
                AzureCredentialsProvider.class.getProtectionDomain().getCodeSource().getLocation().toURI());

        List<String> offenders = new ArrayList<>();
        try (Stream<Path> paths = Files.walk(classesRoot)) {
            List<Path> classFiles = paths.filter(p -> p.toString().endsWith(".class")).toList();
            for (Path classFile : classFiles) {
                String internalName = classesRoot.relativize(classFile).toString().replace(File.separatorChar, '/');
                if (internalName.startsWith(ISOLATION_PACKAGE)) {
                    continue;
                }
                // Class/method/field references live in CONSTANT_Utf8 entries holding the binary name,
                // e.g. "org/jenkinsci/plugins/github_branch_source/GitHubAppCredentials"; a byte scan for
                // the package segment reliably detects any such reference (ISO-8859-1 preserves bytes).
                String contents = new String(Files.readAllBytes(classFile), StandardCharsets.ISO_8859_1);
                if (contents.contains(OPTIONAL_PLUGIN_PACKAGE)) {
                    offenders.add(internalName);
                }
            }
        }

        assertThat(
                "These always-loaded classes reference the optional github-branch-source plugin and will "
                        + "fail to load (NoClassDefFoundError) when it is absent, breaking all credentials. "
                        + "Move the referencing code into " + ISOLATION_PACKAGE + " and gate it behind a "
                        + "plugin-presence check. Offenders: " + offenders,
                offenders, is(empty()));
    }
}
