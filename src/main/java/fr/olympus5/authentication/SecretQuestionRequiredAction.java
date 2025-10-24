package fr.olympus5.authentication;

import fr.olympus5.LoggerUtils;
import fr.olympus5.credential.SecretQuestionCredentialModel;
import fr.olympus5.credential.SecretQuestionCredentialProvider;
import fr.olympus5.credential.SecretQuestionCredentialProviderFactory;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.CredentialRegistrator;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sessions.AuthenticationSessionModel;

public class SecretQuestionRequiredAction implements RequiredActionProvider, CredentialRegistrator {
    public static final String PROVIDER_ID = "secret_question_config";

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        LoggerUtils.markMethodEntry(this.getClass(), "evaluateTriggers");
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        LoggerUtils.markMethodEntry(this.getClass(), "requiredActionChallenge");

        Response challenge = context.form().createForm("secret-question-config.ftl");
        context.challenge(challenge);
    }

    @Override
    public void processAction(RequiredActionContext context) {
        LoggerUtils.markMethodEntry(this.getClass(), "processAction");

        String answer = context.getHttpRequest().getDecodedFormParameters().getFirst("secret_answer");
        SecretQuestionCredentialProvider sqcp = (SecretQuestionCredentialProvider) context.getSession()
                .getProvider(CredentialProvider.class, SecretQuestionCredentialProviderFactory.PROVIDER_ID);
        sqcp.createCredential(context.getRealm(), context.getUser(), SecretQuestionCredentialModel.createSecretQuestion("What is your mom's first name?", answer));

        context.success();
    }

    @Override
    public void close() {
        LoggerUtils.markMethodEntry(this.getClass(), "close");
    }

    @Override
    public String getCredentialType(KeycloakSession session, AuthenticationSessionModel authenticationSession) {
        return SecretQuestionCredentialModel.TYPE;
    }
}
