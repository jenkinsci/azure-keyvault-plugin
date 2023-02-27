package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.azure.core.credential.TokenCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.microsoft.azure.util.AzureCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.FilePath;
import hudson.Util;
import hudson.console.ConsoleLogFilter;
import hudson.model.Item;
import hudson.model.Run;
import hudson.util.ListBoxModel;
import io.jenkins.plugins.azuresdk.HttpClientRetriever;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.security.auth.login.CredentialNotFoundException;
import jenkins.YesNoMaybe;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.plugins.credentialsbinding.masking.SecretPatterns;
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
import org.kohsuke.stapler.verb.POST;

import static java.lang.String.format;
import static java.util.Objects.requireNonNull;
import static org.apache.commons.lang3.ObjectUtils.firstNonNull;
import static org.jenkinsci.plugins.azurekeyvaultplugin.AzureKeyVaultCredentialRetriever.getCredentialById;
import static org.jenkinsci.plugins.azurekeyvaultplugin.AzureKeyVaultCredentialRetriever.getSecretBundle;

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

        return new ExecutionImpl(context, resolvedKeyVaultUrl, resolvedCredentialId, secrets);
    }

    /**
     * Execution for {@link AzureKeyVaultStep}.
     */
    static class ExecutionImpl extends AbstractStepExecutionImpl {

        private final String keyVaultURL;
        private String credentialId;
        private final List<AzureKeyVaultSecret> azureKeyVaultSecrets;

        // legacy section
        private String applicationId;
        private String applicationSecret;
        private String tenantId;
        // end legacy section

        ExecutionImpl(
                StepContext context,
                String keyVaultURL,
                String credentialId,
                List<AzureKeyVaultSecret> azureKeyVaultSecrets
        ) {
            super(context);
            this.keyVaultURL = keyVaultURL;
            this.credentialId = credentialId;
            this.azureKeyVaultSecrets = azureKeyVaultSecrets;
        }

        ExecutionImpl(
                StepContext context,
                String keyVaultURL,
                String applicationId,
                String applicationSecret,
                String tenantId,
                List<AzureKeyVaultSecret> azureKeyVaultSecrets
        ) {
            super(context);
            this.keyVaultURL = keyVaultURL;
            this.applicationId = applicationId;
            this.applicationSecret = applicationSecret;
            this.tenantId = tenantId;
            this.azureKeyVaultSecrets = azureKeyVaultSecrets;
        }


        private static final long serialVersionUID = 1L;

        private boolean isLegacyAuth() {
            return StringUtils.isNotEmpty(applicationId) && StringUtils.isNotEmpty(applicationSecret) && StringUtils.isNotEmpty(tenantId);
        }

        private TokenCredential getCredential(Run<?, ?> run) {
            if (isLegacyAuth()) {
                return new ClientSecretCredentialBuilder()
                        .clientId(applicationId)
                        .clientSecret(applicationSecret)
                        .httpClient(HttpClientRetriever.get())
                        .tenantId(tenantId)
                        .build();
            }

            return getCredentialById(credentialId, run);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean start() throws Exception {
            StepContext context = getContext();
            BodyInvoker invoker = context.newBodyInvoker().withCallback(BodyExecutionCallback.wrap(context));

            Run<?,?> run = context.get(Run.class);
            TokenCredential credential = getCredential(run);

            Map<String, String> secrets = getSecretsMap(credential, keyVaultURL, azureKeyVaultSecrets);

            invoker.withContexts(
                    EnvironmentExpander.merge(context.get(EnvironmentExpander.class), new AzureKeyVaultEnvironmentExpander(secrets)),
                    BodyInvoker.mergeConsoleLogFilters(
                            context.get(ConsoleLogFilter.class),
                            new MaskingConsoleLogFilter(StandardCharsets.UTF_8.name(), SecretPatterns.getAggregateSecretPattern(secrets.values()))
                    )
            );
            invoker.start();
            return false;
        }

        private KeyVaultSecret getSecret(SecretClient client, AzureKeyVaultSecret secret) {
            return getSecretBundle(client, secret);
        }

        private Map<String, String> getSecretsMap(TokenCredential credential, String keyVaultURL, List<AzureKeyVaultSecret> azureKeyVaultSecrets) {
            if (azureKeyVaultSecrets == null || azureKeyVaultSecrets.isEmpty()) {
                return Collections.emptyMap();
            }

            Map<String, String> secrets = new HashMap<>();
            SecretClient client = AzureCredentials.createKeyVaultClient(credential, keyVaultURL);

            for (AzureKeyVaultSecret secret : azureKeyVaultSecrets) {
                if (secret.isPassword()) {
                    KeyVaultSecret bundle = getSecret(client, secret);
                    if (bundle != null) {
                        secrets.put(secret.getEnvVariable(), bundle.getValue());
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
                    KeyVaultSecret bundle = getSecret(client, secret);
                    if (bundle != null) {
                        try {
                            FilePath filePath = requireNonNull(getContext().get(FilePath.class));
                            String path = AzureKeyVaultUtil.convertAndWritePfxToDisk(filePath, bundle.getValue());
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
        @Override @NonNull
        public String getDisplayName() {
            return "Bind credentials in Azure Key Vault to environment variables";
        }

        @SuppressWarnings("unused")
        @POST
        public ListBoxModel doFillCredentialIDItems(@AncestorInPath Item context) {
            return AzureKeyVaultUtil.doFillCredentialIDItems(context);
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
            return Set.of(Run.class);
        }

    }
}
