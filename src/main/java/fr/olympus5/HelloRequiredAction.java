package fr.olympus5;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserModel;

public class HelloRequiredAction implements RequiredActionProvider, RequiredActionFactory {
    private static final String ID = "hello-required-action";
    private static final Logger LOGGER = Logger.getLogger(HelloRequiredAction.class);

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        LOGGER.info("Hello from evaluateTriggers");

        if(context.getUser().getRequiredActionsStream().anyMatch(action -> UserModel.RequiredAction.VERIFY_EMAIL.name().equals(action))) {
            context.getUser().addRequiredAction(ID);
        }
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        LOGGER.info("Hello from requiredActionChallenge");
        processAction(context);
    }

    @Override
    public void processAction(RequiredActionContext context) {
        LOGGER.info("Hello from processAction");
    }

    @Override
    public RequiredActionProvider create(KeycloakSession keycloakSession) {
        return this;
    }

    @Override
    public void init(Config.Scope scope) {

    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayText() {
        return "Hello world action";
    }
}
