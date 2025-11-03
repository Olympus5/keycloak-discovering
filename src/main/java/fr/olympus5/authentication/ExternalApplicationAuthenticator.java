package fr.olympus5.authentication;

import fr.olympus5.LoggerUtils;
import fr.olympus5.token.ExternalApplicationNotificationActionToken;
import fr.olympus5.token.ExternalApplicationNotificationActionTokenHandler;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.TokenVerifier;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Time;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.Urls;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Collections;
import java.util.Objects;

public class ExternalApplicationAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(ExternalApplicationAuthenticator.class);

    public static final String DEFAULT_EXTERNAL_APP_URL = "http://127.0.0.1:8080/action-token-responder-example/external-action.jsp?token={TOKEN}";
    public static final String DEFAULT_APPLICATION_ID = "application-id";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        LoggerUtils.markMethodEntry(this.getClass(), "authenticate");

        String externalApplicationUrl = null;
        String applicationId = null;

        if (context.getAuthenticatorConfig() != null) {
            externalApplicationUrl = context.getAuthenticatorConfig().getConfig().get(ExternalApplicationAuthenticatorFactory.CONFIG_EXTERNAL_APP_URL);
            applicationId = context.getAuthenticatorConfig().getConfig().get(ExternalApplicationAuthenticatorFactory.CONFIG_APPLICATION_ID);
        }

        if (externalApplicationUrl == null) {
            externalApplicationUrl = DEFAULT_EXTERNAL_APP_URL;
        }

        if (applicationId == null) {
            applicationId = DEFAULT_APPLICATION_ID;
        }

        int validityInSecs = context.getRealm().getActionTokenGeneratedByUserLifespan();
        int absoluteExpirationInSecs = Time.currentTime() + validityInSecs;
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String clientId = authSession.getClient().getClientId();
        String token = new ExternalApplicationNotificationActionToken(
                context.getUser().getId(),
                absoluteExpirationInSecs,
                authSession.getParentSession().getId(),
                applicationId
        ).serialize(
                context.getSession(),
                context.getRealm(),
                context.getUriInfo()
        );
        String submitActionTokenUrl = Urls.actionTokenBuilder(
                        context.getUriInfo().getBaseUri(),
                        token,
                        clientId,
                        authSession.getTabId(),
                        "")
                .queryParam(Constants.EXECUTION, context.getExecution().getId())
                .queryParam(ExternalApplicationNotificationActionTokenHandler.QUERY_PARAM_APP_TOKEN, "{tokenParameterName}")
                .build(context.getRealm().getName(), "{APP_TOKEN}")
                .toString();

        try {
            Response challenge = Response.status(Response.Status.FOUND)
                    .header("Location", externalApplicationUrl.replace("{TOKEN}", URLEncoder.encode(submitActionTokenUrl, "UTF-8")))
                    .build();

            context.challenge(challenge);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        LoggerUtils.markMethodEntry(this.getClass(), "action");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        if (Objects.equals(authSession.getAuthNote(ExternalApplicationNotificationActionTokenHandler.INITIATED_BY_ACTION_TOKEN_EXT_APP), "true")) {
            authenticate(context);
            return;
        }

        authSession.removeAuthNote(ExternalApplicationNotificationActionTokenHandler.INITIATED_BY_ACTION_TOKEN_EXT_APP);

        String appTokenString = context.getUriInfo().getQueryParameters().getFirst(ExternalApplicationNotificationActionTokenHandler.QUERY_PARAM_APP_TOKEN);
        UserModel user = authSession.getAuthenticatedUser();
        String applicationId = null;

        if (context.getAuthenticatorConfig() != null) {
            applicationId = context.getAuthenticatorConfig().getConfig().get(ExternalApplicationAuthenticatorFactory.CONFIG_APPLICATION_ID);
        }

        if (applicationId == null) {
            applicationId = DEFAULT_APPLICATION_ID;
        }

        try {
            JsonWebToken appToken = TokenVerifier.create(appTokenString, JsonWebToken.class).getToken();
            final String appId = applicationId;
            appToken.getOtherClaims().forEach((k, v) ->
                    user.setAttribute(appId + "." + k, Collections.singletonList(String.valueOf(v))));
        } catch (VerificationException e) {
            throw new RuntimeException(e);
        }

        context.success();
    }

    @Override
    public boolean requiresUser() {
        LoggerUtils.markMethodEntry(this.getClass(), "requiresUser");

        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        LoggerUtils.markMethodEntry(this.getClass(), "configuredFor");

        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        LoggerUtils.markMethodEntry(this.getClass(), "setRequiredActions");
    }

    @Override
    public void close() {
        LoggerUtils.markMethodEntry(this.getClass(), "close");
    }
}
