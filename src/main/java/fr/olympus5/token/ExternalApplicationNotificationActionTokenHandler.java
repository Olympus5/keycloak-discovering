package fr.olympus5.token;

import fr.olympus5.LoggerUtils;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.TokenVerifier;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.authentication.actiontoken.TokenUtils;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Base64;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;

public class ExternalApplicationNotificationActionTokenHandler extends AbstractActionTokenHandler<ExternalApplicationNotificationActionToken> {

    private static final Logger LOGGER = Logger.getLogger(ExternalApplicationNotificationActionTokenHandler.class);

    public static final String QUERY_PARAM_APP_TOKEN = "app-token";
    public static final String INITIATED_BY_ACTION_TOKEN_EXT_APP = "INITIATED_BY_ACTION_TOKEN_EXT_APP";

    private SecretKeySpec hmacSecretKeySpec = null;

    public ExternalApplicationNotificationActionTokenHandler() {
        super(
                ExternalApplicationNotificationActionToken.TOKEN_TYPE,
                ExternalApplicationNotificationActionToken.class,
                Messages.INVALID_REQUEST,
                EventType.EXECUTE_ACTION_TOKEN,
                Errors.INVALID_REQUEST
        );
    }

    @Override
    public TokenVerifier.Predicate<? super ExternalApplicationNotificationActionToken>[] getVerifiers(ActionTokenContext<ExternalApplicationNotificationActionToken> tokenContext) {
        LoggerUtils.markMethodEntry(this.getClass(), "getVerifiers");

        return TokenUtils.predicates(
                t -> tokenContext.getUriInfo().getQueryParameters().getFirst(QUERY_PARAM_APP_TOKEN) == null,
                t -> isApplicationTokenValid(t, tokenContext)
        );
    }

    private boolean isApplicationTokenValid(ExternalApplicationNotificationActionToken token, ActionTokenContext<ExternalApplicationNotificationActionToken> tokenContext) throws VerificationException {
        LoggerUtils.markMethodEntry(this.getClass(), "isApplicationTokenValid");

        String appTokenString = tokenContext.getUriInfo().getQueryParameters().getFirst(QUERY_PARAM_APP_TOKEN);

        TokenVerifier.create(appTokenString, JsonWebToken.class)
                .secretKey(hmacSecretKeySpec)
                .verify();

        return true;
    }

    @Override
    public Response handleToken(ExternalApplicationNotificationActionToken token, ActionTokenContext<ExternalApplicationNotificationActionToken> tokenContext) {
        LoggerUtils.markMethodEntry(this.getClass(), "handleToken");

        tokenContext.getAuthenticationSession().setAuthNote(INITIATED_BY_ACTION_TOKEN_EXT_APP, "true");

        return tokenContext.processFlow(
                true,
                LoginActionsService.AUTHENTICATE_PATH,
                tokenContext.getRealm().getBrowserFlow(),
                null,
                new AuthenticationProcessor());
    }

    @Override
    public String getAuthenticationSessionIdFromToken(ExternalApplicationNotificationActionToken token, ActionTokenContext<ExternalApplicationNotificationActionToken> tokenContext, AuthenticationSessionModel currentAuthSession) {
        LoggerUtils.markMethodEntry(this.getClass(), "getAuthenticationSessionIdFromToken");

        String id = currentAuthSession == null ? null : AuthenticationSessionCompoundId.fromAuthSession(currentAuthSession).getEncodedId();

        LOGGER.infof("Returning %s", id);

        return id;
    }

    @Override
    public void init(Config.Scope config) {
        String secret = config.get("hmacSecret", null);

        if (secret == null) {
            throw new RuntimeException("You have to configure HMAC secret");
        }

        try {
            this.hmacSecretKeySpec = new SecretKeySpec(Base64.decode(secret), "HmacSHA256");
        } catch (IOException e) {
            throw new RuntimeException("Cannot decode HMAC secret from string", e);
        }
    }
}
