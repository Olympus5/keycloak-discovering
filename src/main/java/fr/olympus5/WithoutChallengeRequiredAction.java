package fr.olympus5;

import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserModel;

public class WithoutChallengeRequiredAction implements RequiredActionProvider, RequiredActionFactory {
    private static final String ID = "hello-required-action";

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        LoggerUtils.markMethodEntry(this.getClass(), "evaluateTriggers");

        if (context.getUser().getRequiredActionsStream().anyMatch(action -> UserModel.RequiredAction.VERIFY_EMAIL.name().equals(action))) {
            context.getUser().addRequiredAction(ID);
        }
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        LoggerUtils.markMethodEntry(this.getClass(), "requiredActionChallenge");
        this.processAction(context);
    }

    @Override
    public void processAction(RequiredActionContext context) {
        LoggerUtils.markMethodEntry(this.getClass(), "processAction");
    }

    @Override
    public RequiredActionProvider create(KeycloakSession keycloakSession) {
        LoggerUtils.markMethodEntry(this.getClass(), "create");
        return this;
    }

    @Override
    public void init(Config.Scope scope) {
        LoggerUtils.markMethodEntry(this.getClass(), "init");
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
        LoggerUtils.markMethodEntry(this.getClass(), "postInit");
    }

    @Override
    public void close() {
        LoggerUtils.markMethodEntry(this.getClass(), "close");
    }

    @Override
    public String getId() {
        LoggerUtils.markMethodEntry(this.getClass(), "getId");
        return ID;
    }

    @Override
    public String getDisplayText() {
        LoggerUtils.markMethodEntry(this.getClass(), "getDisplayText");
        return "Hello world action";
    }
}
