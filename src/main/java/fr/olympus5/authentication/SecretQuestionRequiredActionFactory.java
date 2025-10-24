package fr.olympus5.authentication;

import fr.olympus5.LoggerUtils;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class SecretQuestionRequiredActionFactory implements RequiredActionFactory {
    private static final SecretQuestionRequiredAction SINGLETON = new  SecretQuestionRequiredAction();

    @Override
    public String getDisplayText() {
        LoggerUtils.markMethodEntry(this.getClass(), "getDisplayText");

        return "Secret Question";
    }

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        LoggerUtils.markMethodEntry(this.getClass(), "create");

        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
        LoggerUtils.markMethodEntry(this.getClass(), "init");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        LoggerUtils.markMethodEntry(this.getClass(), "postInit");
    }

    @Override
    public void close() {
        LoggerUtils.markMethodEntry(this.getClass(), "close");
    }

    @Override
    public String getId() {
        LoggerUtils.markMethodEntry(this.getClass(), "getId");

        return SecretQuestionRequiredAction.PROVIDER_ID;
    }
}
