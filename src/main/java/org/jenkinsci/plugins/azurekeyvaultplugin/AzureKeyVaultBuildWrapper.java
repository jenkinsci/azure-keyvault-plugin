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

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Item;
import hudson.model.Run;
import hudson.util.ListBoxModel;
import jenkins.YesNoMaybe;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.plugins.workflow.steps.Step;
import org.jenkinsci.plugins.workflow.steps.StepContext;
import org.jenkinsci.plugins.workflow.steps.StepDescriptor;
import org.jenkinsci.plugins.workflow.steps.StepExecution;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.verb.POST;

import javax.annotation.CheckForNull;
import javax.security.auth.login.CredentialNotFoundException;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import static hudson.Util.fixEmpty;
import static org.apache.commons.lang3.ObjectUtils.firstNonNull;

/**
 * Wraps a build with azure key vault secrets / certificates
 * @deprecated use {@link AzureKeyVaultStep}
 */
@Deprecated(forRemoval = true)
public class AzureKeyVaultBuildWrapper extends Step {

    private static final Logger LOGGER = Logger.getLogger("Jenkins.AzureKeyVaultBuildWrapper");

    private final List<AzureKeyVaultSecret> azureKeyVaultSecrets;
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

    public String getApplicationID() {
        return applicationID;
    }

    public List<AzureKeyVaultSecret> getAzureKeyVaultSecrets() {
        return azureKeyVaultSecrets;
    }

    @Override
    public StepExecution start(StepContext context) throws Exception {
        AzureKeyVaultGlobalConfiguration globalConfiguration = AzureKeyVaultGlobalConfiguration.get();
        String resolvedKeyVaultUrl = firstNonNull(keyVaultURL, globalConfiguration.getKeyVaultURL());

        if (StringUtils.isEmpty(resolvedKeyVaultUrl)) {
            throw new AzureKeyVaultException("No key vault url configured, set one globally or in the build wrap step");
        }

        String resolvedCredentialId = firstNonNull(credentialID, globalConfiguration.getCredentialID());

        if (StringUtils.isNotEmpty(applicationSecret)) {
            // Implement some compatibility here
            LOGGER.info("HITTING LEGACY CODE PATH");
        }

        if  (StringUtils.isEmpty(resolvedCredentialId)) {
            throw new CredentialNotFoundException("Unable to find a valid credential with provided parameters");
        }

        return new AzureKeyVaultStep.ExecutionImpl(context, resolvedKeyVaultUrl, resolvedCredentialId, azureKeyVaultSecrets);
    }


    /**
     * Descriptor for {@link AzureKeyVaultStep}.
     */
    @Extension(dynamicLoadable = YesNoMaybe.YES, optional = true)
    public static class DescriptorImpl extends StepDescriptor {

        @SuppressWarnings("unused")
        @POST
        public ListBoxModel doFillCredentialIDOverrideItems(@AncestorInPath Item context) {
            return AzureKeyVaultUtil.doFillCredentialIDItems(context);
        }

        /**
         * This human-readable name is used in the snippet generator for pipeline.
         */
        @NonNull
        public String getDisplayName() {
            return "Bind credentials in Azure Key Vault to variables";
        }

        @Override
        public Set<? extends Class<?>> getRequiredContext() {
            return Set.of(Run.class);
        }

        @Override
        public String getFunctionName() {
            return "withAzureKeyvault";
        }
    }
}
