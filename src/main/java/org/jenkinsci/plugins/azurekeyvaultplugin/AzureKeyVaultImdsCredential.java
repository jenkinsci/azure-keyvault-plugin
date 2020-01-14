package org.jenkinsci.plugins.azurekeyvaultplugin;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import com.microsoft.jenkins.azurecommons.core.credentials.AbstractTokenCredentials;
import java.io.IOException;
import java.io.Serializable;
import java.util.Objects;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.logging.HttpLoggingInterceptor;

public class AzureKeyVaultImdsCredential extends KeyVaultCredentials implements Serializable {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    @Override
    public String doAuthenticate(String authorization, String resource, String scope) {
        HttpLoggingInterceptor loggingInterceptor = new HttpLoggingInterceptor();
        loggingInterceptor.setLevel(HttpLoggingInterceptor.Level.BASIC);

        OkHttpClient client = new OkHttpClient.Builder()
                .addInterceptor(loggingInterceptor)
                .build();

        Request request;
        try {
            request = new Request.Builder()
                    .addHeader("Metadata", "true")
                    .url("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=" + resource)
                    .build();

            Response response = client.newCall(request).execute();
            if (!response.isSuccessful()) {
                throw new AzureKeyVaultException("Failure getting IMDS credential: " + response.code() + " " + response.message());
            } else {
                return parseToken(Objects.requireNonNull(response.body()).string()).getAccessToken();
            }

        } catch (IOException e) {
            throw new AzureKeyVaultException("Failure getting IMDS credential: ", e);
        }

    }

    protected AbstractTokenCredentials.Token parseToken(final String responseBody) throws IOException {
        AbstractTokenCredentials.Token token = MAPPER.readValue(responseBody, AbstractTokenCredentials.Token.class);
        if (token == null) {
            throw new RuntimeException("Failed to parse the response.");
        } else if (token.getAccessToken() == null || token.getAccessToken().equals("")) {
            throw new RuntimeException("The access token isn't included in the response.");
        } else {
            return token;
        }
    }
}
