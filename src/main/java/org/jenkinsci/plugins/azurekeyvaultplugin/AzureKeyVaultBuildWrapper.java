/*
 * The MIT License (MIT)
 * <p>
 * Copyright (c) 2017 Microsoft Corporation
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.azure.core.credential.TokenCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.microsoft.azure.util.AzureCredentials;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.console.ConsoleLogFilter;
import hudson.model.AbstractProject;
import hudson.model.Item;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.BuildWrapperDescriptor;
import hudson.util.ListBoxModel;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import jenkins.tasks.SimpleBuildWrapper;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.verb.POST;

import static hudson.Util.fixEmpty;
import static java.lang.String.format;
import static org.jenkinsci.plugins.azurekeyvaultplugin.AzureKeyVaultCredentialRetriever.getCredentialById;
import static org.jenkinsci.plugins.azurekeyvaultplugin.AzureKeyVaultCredentialRetriever.getSecretBundle;

/**
 * Wraps a build with azure key vault secrets / certificates
 */
public class AzureKeyVaultBuildWrapper extends SimpleBuildWrapper {

    private static final Logger LOGGER = Logger.getLogger("Jenkins.AzureKeyVaultBuildWrapper");

    private final List<AzureKeyVaultSecret> azureKeyVaultSecrets;
    private final List<String> valuesToMask = new ArrayList<>();

    // Instances for this particular build job so they can override the global settings
    private String keyVaultURL;
    private String applicationID;
    private String applicationSecret;
    private String credentialID;
    private String tenantId;

    @DataBoundConstructor
    public AzureKeyVaultBuildWrapper(@CheckForNull List<AzureKeyVaultSecret> azureKeyVaultSecrets) {
        this.azureKeyVaultSecrets = azureKeyVaultSecrets;
    }

    // Override KeyVault URL
    public String getKeyVaultURLOverride() {
        return this.keyVaultURL;
    }

    @DataBoundSetter
    public void setKeyVaultURLOverride(String keyVaultURL) {
        this.keyVaultURL = fixEmpty(keyVaultURL);
    }

    // Override KeyVault Application ID
    public String getApplicationIDOverride() {
        return this.applicationID;
    }

    @DataBoundSetter
    public void setApplicationIDOverride(String applicationID) {
        this.applicationID = fixEmpty(applicationID);
    }

    // Override Application Secret
    public String getApplicationSecretOverride() {
        return this.applicationSecret;
    }

    @DataBoundSetter
    public void setApplicationSecretOverride(String applicationSecret) {
        this.applicationSecret = fixEmpty(applicationSecret);
    }

    // Override Application Secret ID
    public String getCredentialIDOverride() {
        return this.credentialID;
    }

    @DataBoundSetter
    public void setCredentialIDOverride(String credentialID) {
        this.credentialID = fixEmpty(credentialID);
    }

    public String getTenantIdOverride() {
        return this.tenantId;
    }

    @DataBoundSetter
    public void setTenantIdOverride(String tenantId) {
        this.tenantId = fixEmpty(tenantId);
    }

    // Get the default value only if it is not overridden for this build
    public String getKeyVaultURL() {
        AzureKeyVaultGlobalConfiguration globalConfiguration = AzureKeyVaultGlobalConfiguration.get();

        if (StringUtils.isNotEmpty(keyVaultURL)) {
            return keyVaultURL;
        }
        if (StringUtils.isNotEmpty(globalConfiguration.getKeyVaultURL())) {
            return globalConfiguration.getKeyVaultURL();
        } else {
            throw new AzureKeyVaultException("No key vault url configured, set one globally or in the build wrap step");
        }
    }

    @Override
    public ConsoleLogFilter createLoggerDecorator(@Nonnull final Run<?, ?> build) {
        return new MaskingConsoleLogFilter(build.getCharset().name(), valuesToMask);
    }


    public TokenCredential getKeyVaultCredential(Run<?, ?> build) {
        // Try override values
        LOGGER.fine("Trying override credentials...");
        TokenCredential credential = getKeyVaultCredential(build, this.applicationSecret, this.credentialID, this.tenantId);
        if (credential != null) {
            LOGGER.fine("Using override credentials");
            return credential;
        }

        // Try global values
        LOGGER.fine("Trying global credentials");
        credential = getKeyVaultCredential(
                build,
                null,
                AzureKeyVaultGlobalConfiguration.get().getCredentialID(),
                null
        );

        if (credential != null) {
            return credential;
        }

        throw new AzureKeyVaultException("Unable to find a valid credential with provided parameters");
    }

    @CheckForNull
    public TokenCredential getKeyVaultCredential(Run<?, ?> build, String applicationSecret, String credentialID, String tenantId) {
        if (StringUtils.isNotEmpty(credentialID)) {
            LOGGER.fine("Fetching credentials by ID");
            return getCredentialById(credentialID, build);
        }

        // Try AppID/Secret
        if (StringUtils.isNotEmpty(applicationSecret)) {
            if (StringUtils.isEmpty(tenantId)) {
                throw new IllegalArgumentException("Set `tenantId` in your withAzureKeyVault configuration, or migrate " +
                        "to using either a 'Microsoft Azure Service Principal' or a 'Managed Identities for Azure Resources'");
            }
            // Allowed in pipeline, but not global  config
            LOGGER.fine("Using explicit application secret.");
            return new ClientSecretCredentialBuilder()
                    .clientId(getApplicationID())
                    .clientSecret(applicationSecret)
                    .tenantId(tenantId)
                    .build();
        }

        return null;
    }

    public String getApplicationID() {
        if (StringUtils.isNotEmpty(applicationID)) {
            LOGGER.fine("Using override Application ID");
            return applicationID;
        }
        return null;
    }

    public List<AzureKeyVaultSecret> getAzureKeyVaultSecrets() {
        return azureKeyVaultSecrets;
    }

    // Overridden for better type safety.
    // If your plugin doesn't really define any property on Descriptor,
    // you don't have to do this.
    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) super.getDescriptor();
    }

    private KeyVaultSecret getSecret(SecretClient client, AzureKeyVaultSecret secret) {
        return getSecretBundle(client, secret);
    }

    public void setUp(Context context, Run<?, ?> build, FilePath workspace,
                      Launcher launcher, TaskListener listener, EnvVars initialEnvironment) {
        if (azureKeyVaultSecrets == null || azureKeyVaultSecrets.isEmpty()) {
            return;
        }

        SecretClient client = AzureCredentials.createKeyVaultClient(getKeyVaultCredential(build), getKeyVaultURL());

        for (AzureKeyVaultSecret secret : azureKeyVaultSecrets) {
            if (secret.isPassword()) {
                KeyVaultSecret bundle = getSecret(client, secret);
                if (bundle != null) {
                    valuesToMask.add(bundle.getValue());
                    context.env(secret.getEnvVariable(), bundle.getValue());
                } else {
                    throw new AzureKeyVaultException(
                            format(
                                    "Secret: %s not found in vault: %s",
                                    secret.getName(),
                                    getKeyVaultURL()
                            )
                    );
                }
            } else if (secret.isCertificate()) {
                // Get Certificate from Keyvault as a Secret
                KeyVaultSecret bundle = getSecret(client, secret);
                if (bundle != null) {
                    try {
                        String path = AzureKeyVaultUtil.convertAndWritePfxToDisk(workspace, bundle.getValue());
                        context.env(secret.getEnvVariable(), path);
                    } catch (Exception e) {
                        throw new AzureKeyVaultException(e.getMessage(), e);
                    }
                } else {
                    throw new AzureKeyVaultException(
                            format(
                                    "Certificate: %s not found in vault: %s",
                                    secret.getName(),
                                    getKeyVaultURL()
                            )
                    );
                }
            }
        }
    }

    /**
     * Descriptor for {@link AzureKeyVaultBuildWrapper}. Used as a singleton.
     * The class is marked as public so that it can be accessed from views.
     *
     * <p>
     * for the actual HTML fragment for the configuration screen.
     */
    @Extension
    @Symbol("withAzureKeyvault")
    public static final class DescriptorImpl extends BuildWrapperDescriptor {

        public DescriptorImpl() {
            super(AzureKeyVaultBuildWrapper.class);
            load();
        }

        @SuppressWarnings("unused")
        @POST
        public ListBoxModel doFillCredentialIDOverrideItems(@AncestorInPath Item context) {
            return AzureKeyVaultUtil.doFillCredentialIDItems(context);
        }

        @Override
        public boolean isApplicable(AbstractProject<?, ?> item) {
            return true;
        }

        /**
         * This human readable name is used in the snippet generator for pipeline.
         */
        public String getDisplayName() {
            return "Bind credentials in Azure Key Vault to variables";
        }
    }
}
