/*
 * The MIT License
 *
 * Copyright (c) 2016 Steven G. Brown
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.google.common.collect.ImmutableSet;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.models.SecretBundle;
import hudson.Extension;
import hudson.console.ConsoleLogFilter;
import hudson.model.Run;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.security.auth.login.CredentialNotFoundException;
import jenkins.YesNoMaybe;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.plugins.workflow.steps.AbstractStepExecutionImpl;
import org.jenkinsci.plugins.workflow.steps.BodyExecutionCallback;
import org.jenkinsci.plugins.workflow.steps.BodyInvoker;
import org.jenkinsci.plugins.workflow.steps.EnvironmentExpander;
import org.jenkinsci.plugins.workflow.steps.Step;
import org.jenkinsci.plugins.workflow.steps.StepContext;
import org.jenkinsci.plugins.workflow.steps.StepDescriptor;
import org.jenkinsci.plugins.workflow.steps.StepExecution;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import static com.google.common.base.MoreObjects.firstNonNull;
import static java.lang.String.format;
import static org.jenkinsci.plugins.azurekeyvaultplugin.AzureKeyVaultCredentialRetriever.getCredentialById;

/**
 * Pipeline plug-in step for recording time-stamps.
 */
public class AzureKeyVaultStep extends Step {

    private final List<AzureKeyVaultSecret> secrets;
    private String keyVaultURL;
    private String credentialID;

    @DataBoundConstructor
    public AzureKeyVaultStep(@CheckForNull List<AzureKeyVaultSecret> secrets) {
        this.secrets = secrets;
    }

    public List<AzureKeyVaultSecret> getSecrets() {
        return secrets;
    }

    public String getKeyVaultURL() {
        return keyVaultURL;
    }

    @DataBoundSetter
    public void setKeyVaultURL(String keyVaultURL) {
        this.keyVaultURL = keyVaultURL;
    }

    public String getCredentialID() {
        return credentialID;
    }

    public void setCredentialID(String credentialID) {
        this.credentialID = credentialID;
    }

    @Override
    public StepExecution start(StepContext context) throws Exception {
        AzureKeyVaultGlobalConfiguration globalConfiguration = AzureKeyVaultGlobalConfiguration.get();
        String resolvedKeyVaultUrl = firstNonNull(keyVaultURL, globalConfiguration.getKeyVaultURL());

        if (StringUtils.isEmpty(resolvedKeyVaultUrl)) {
            throw new AzureKeyVaultException("No key vault url configured, set one globally or in the build wrap step");
        }

        String resolvedCredentialId = firstNonNull(credentialID, globalConfiguration.getCredentialID());
        if  (StringUtils.isEmpty(resolvedCredentialId)) {
            throw new CredentialNotFoundException("Unable to find a valid credential with provided parameters");
        }

        Run run = context.get(Run.class);
        AzureKeyVaultCredential credential = getCredentialById(resolvedCredentialId, run);

        return new ExecutionImpl(context, resolvedKeyVaultUrl, credential, secrets);
    }

    /**
     * Execution for {@link AzureKeyVaultStep}.
     */
    private static class ExecutionImpl extends AbstractStepExecutionImpl {

        private final String keyVaultURL;
        private final AzureKeyVaultCredential credential;
        private final List<AzureKeyVaultSecret> azureKeyVaultSecrets;

        ExecutionImpl(
                StepContext context,
                String keyVaultURL,
                AzureKeyVaultCredential credential,
                List<AzureKeyVaultSecret> azureKeyVaultSecrets
        ) {
            super(context);
            this.keyVaultURL = keyVaultURL;
            this.credential = credential;
            this.azureKeyVaultSecrets = azureKeyVaultSecrets;
        }

        private static final long serialVersionUID = 1L;

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean start() throws Exception {
            StepContext context = getContext();
            BodyInvoker invoker = context.newBodyInvoker().withCallback(BodyExecutionCallback.wrap(context));

            Map<String, String> secrets = getSecretsMap(credential, keyVaultURL, azureKeyVaultSecrets);

            invoker.withContexts(
                    EnvironmentExpander.merge(context.get(EnvironmentExpander.class), new AzureKeyVaultEnvironmentExpander(secrets)),
                    BodyInvoker.mergeConsoleLogFilters(
                            context.get(ConsoleLogFilter.class),
                            new MaskingConsoleLogFilter(StandardCharsets.UTF_8.name(), new ArrayList<>(secrets.values()))
                    )
            );
            invoker.start();
            return false;
        }

        private SecretBundle getSecret(KeyVaultClient client, String keyVaultURL, AzureKeyVaultSecret secret) {
            try {
                return client.getSecret(keyVaultURL, secret.getName(), secret.getVersion());
            } catch (Exception e) {
                throw new AzureKeyVaultException(
                        format(
                                "Failed to retrieve secret %s from vault %s, error message: %s",
                                secret.getName(),
                                keyVaultURL,
                                e.getMessage()
                        ), e);
            }
        }

        private Map<String, String> getSecretsMap(AzureKeyVaultCredential credential, String keyVaultURL, List<AzureKeyVaultSecret> azureKeyVaultSecrets) {
            if (azureKeyVaultSecrets == null || azureKeyVaultSecrets.isEmpty()) {
                return Collections.emptyMap();
            }

            Map<String, String> secrets = new HashMap<>();
            KeyVaultClient client = new KeyVaultClient(credential);

            for (AzureKeyVaultSecret secret : azureKeyVaultSecrets) {
                if (secret.isPassword()) {
                    SecretBundle bundle = getSecret(client, keyVaultURL, secret);
                    if (bundle != null) {
                        secrets.put(secret.getEnvVariable(), bundle.value());
                    } else {
                        throw new AzureKeyVaultException(
                                format(
                                        "Secret: %s not found in vault: %s",
                                        secret.getName(),
                                        keyVaultURL
                                )
                        );
                    }
                } else if (secret.isCertificate()) {
                    throw new AzureKeyVaultException("Certificate is not currently supported in the azureKeyVault step, use the `withAzureKeyvault` build wrapper");
                }
            }
            return secrets;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void stop(@Nonnull Throwable cause) {
            getContext().onFailure(cause);
        }
    }

    /**
     * Descriptor for {@link AzureKeyVaultStep}.
     */
    @Extension(dynamicLoadable = YesNoMaybe.YES, optional = true)
    public static class DescriptorImpl extends StepDescriptor {

        /**
         * {@inheritDoc}
         */
        @Override
        public String getDisplayName() {
            return "azureKeyVault";
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getFunctionName() {
            return "azureKeyVault";
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean takesImplicitBlockArgument() {
            return true;
        }

        @Override
        public Set<? extends Class<?>> getRequiredContext() {
            return ImmutableSet.of(Run.class);
        }

    }
}
