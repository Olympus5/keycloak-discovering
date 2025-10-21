package fr.olympus5;

import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;

public class SecretQuestionCredentialProviderFactory implements CredentialProviderFactory<SecretQuestionCredentialProvider> {
    public static final String PROVIDER_ID = "secret-question";

    @Override
    public CredentialProvider create(KeycloakSession session) {
        LoggerUtils.markMethodEntry(this.getClass(), "create");

        return new SecretQuestionCredentialProvider(session);
    }

    @Override
    public String getId() {
        LoggerUtils.markMethodEntry(this.getClass(), "getId");

        return PROVIDER_ID;
    }
}
