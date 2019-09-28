package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.google.common.collect.ImmutableSet;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.models.SecretBundle;
import com.microsoft.azure.util.AzureCredentials;
import hudson.Extension;
import hudson.FilePath;
import hudson.Util;
import hudson.console.ConsoleLogFilter;
import hudson.model.Item;
import hudson.model.Run;
import hudson.security.ACL;
import hudson.util.ListBoxModel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import static com.google.common.base.MoreObjects.firstNonNull;
import static java.lang.String.format;
import static java.util.Objects.requireNonNull;
import static org.jenkinsci.plugins.azurekeyvaultplugin.AzureKeyVaultCredentialRetriever.getCredentialById;

public class AzureKeyVaultStep extends Step {

    private final List<AzureKeyVaultSecret> secrets;
    private String keyVaultURL;
    private String credentialID;

    @DataBoundConstructor
    public AzureKeyVaultStep(List<AzureKeyVaultSecret> secrets) {
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
        this.keyVaultURL = Util.fixEmpty(keyVaultURL);
    }

    public String getCredentialID() {
        return credentialID;
    }

    @DataBoundSetter
    public void setCredentialID(String credentialID) {
        this.credentialID = Util.fixEmpty(credentialID);
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
                    SecretBundle bundle = getSecret(client, keyVaultURL, secret);
                    if (bundle != null) {
                        try {
                            FilePath filePath = requireNonNull(getContext().get(FilePath.class));
                            String path = AzureKeyVaultUtil.convertAndWritePfxToDisk(filePath, bundle.value());
                            secrets.put(secret.getEnvVariable(), path);
                        } catch (Exception e) {
                            throw new AzureKeyVaultException(e.getMessage(), e);
                        }
                    } else {
                        throw new AzureKeyVaultException(
                                format(
                                        "Certificate: %s not found in vault: %s",
                                        secret.getName(),
                                        keyVaultURL
                                )
                        );
                    }
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

        @SuppressWarnings("unused")
        public ListBoxModel doFillCredentialIDItems(@AncestorInPath Item context) {
            return new StandardListBoxModel().includeEmptyValue()
                    .includeAs(ACL.SYSTEM, context, StandardUsernamePasswordCredentials.class)
                    .includeAs(ACL.SYSTEM, context, AzureCredentials.class);
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
