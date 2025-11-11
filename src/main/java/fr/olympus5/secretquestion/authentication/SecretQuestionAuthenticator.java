package fr.olympus5.secretquestion.authentication;

import fr.olympus5.LoggerUtils;
import fr.olympus5.secretquestion.credential.SecretQuestionCredentialProvider;
import fr.olympus5.secretquestion.credential.SecretQuestionCredentialProviderFactory;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.*;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.*;

import java.net.URI;
import java.util.Collections;
import java.util.List;

public class SecretQuestionAuthenticator implements Authenticator, CredentialValidator<SecretQuestionCredentialProvider> {
    private static final Logger LOGGER = Logger.getLogger(SecretQuestionAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        LoggerUtils.markMethodEntry(this.getClass(), "authenticate");

        if (hasCookie(context)) {
            context.success();
            return;
        }

        Response challenge = context.form()
                .createForm("secret-question.ftl");
        context.challenge(challenge);
    }

    private boolean hasCookie(AuthenticationFlowContext context) {
        Cookie cookie = context.getHttpRequest().getHttpHeaders().getCookies().get("SECRET_QUESTION_ANSWERED");

        boolean result = cookie != null;

        if (result) {
            LOGGER.info("Bypassing secret question because cookie is set");
        }

        return result;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        LoggerUtils.markMethodEntry(this.getClass(), "action");

        boolean validated = validateAnswer(context);

        if (!validated) {
            Response challenge = context.form()
                    .setError("badSecret")
                    .createForm("secret-question.ftl");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            return;
        }

        setCookie(context);
        context.success();
    }

    private boolean validateAnswer(AuthenticationFlowContext context) {
        LoggerUtils.markMethodEntry(this.getClass(), "validateAnswer");

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String secret = formData.getFirst("secret_answer");
        String credentialId = formData.getFirst("credentialId");

        if (credentialId == null || credentialId.isEmpty()) {
            credentialId = getCredentialProvider(context.getSession())
                    .getDefaultCredential(context.getSession(), context.getRealm(), context.getUser()).getId();
        }

        UserCredentialModel input = new UserCredentialModel(credentialId, getType(context.getSession()), secret);

        return getCredentialProvider(context.getSession()).isValid(context.getRealm(), context.getUser(), input);
    }

    private void setCookie(AuthenticationFlowContext context) {
        LoggerUtils.markMethodEntry(this.getClass(), "setCookie");

        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        int maxCookieAge = 60 * 60 * 24 * 30;
        if (config != null) {
            maxCookieAge = Integer.valueOf(config.getConfig().get("cookie.max.age"));
        }

        URI uri = context.getUriInfo().getBaseUriBuilder().path("realms").path(context.getRealm().getName()).build();

        NewCookie newCookie = new NewCookie.Builder("SECRET_QUESTION_ANSWERED").value("true")
                .path(uri.getRawPath())
                .maxAge(maxCookieAge)
                .secure(false)
                .build();
        context.getSession().getContext().getHttpResponse().setCookieIfAbsent(newCookie);
    }

    @Override
    public boolean requiresUser() {
        LoggerUtils.markMethodEntry(this.getClass(), "requiresUser");

        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        LoggerUtils.markMethodEntry(this.getClass(), "configuredFor");

        return getCredentialProvider(session).isConfiguredFor(realm, user, getType(session));
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        LoggerUtils.markMethodEntry(this.getClass(), "setRequiredActions");

        user.addRequiredAction(SecretQuestionRequiredAction.PROVIDER_ID);
    }

    @Override
    public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) {
        return Collections.singletonList((SecretQuestionRequiredActionFactory)session.getKeycloakSessionFactory().getProviderFactory(RequiredActionProvider.class, SecretQuestionRequiredAction.PROVIDER_ID));
    }

    @Override
    public SecretQuestionCredentialProvider getCredentialProvider(KeycloakSession session) {
        LoggerUtils.markMethodEntry(this.getClass(), "getCredentialProvider");

        return (SecretQuestionCredentialProvider) session.getProvider(CredentialProvider.class, SecretQuestionCredentialProviderFactory.PROVIDER_ID);
    }

    @Override
    public void close() {
        LoggerUtils.markMethodEntry(this.getClass(), "close");
    }
}
