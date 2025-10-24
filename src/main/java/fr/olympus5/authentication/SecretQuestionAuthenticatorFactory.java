package fr.olympus5.authentication;

import fr.olympus5.LoggerUtils;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class SecretQuestionAuthenticatorFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {

    public static final String PROVIDER_ID = "secret-question-authenticator";
    private static final SecretQuestionAuthenticator SINGLETON = new SecretQuestionAuthenticator();
    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED,
    };
    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName("cookie.max.age");
        property.setLabel("Cookie Max Age");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Maximum age in seconds of SECRET_QUESTION_COOKIE.");
        CONFIG_PROPERTIES.add(property);
    }

    @Override
    public String getDisplayType() {
        LoggerUtils.markMethodEntry(this.getClass(), "getDisplayType");

        return "Secret Question";
    }

    @Override
    public String getReferenceCategory() {
        LoggerUtils.markMethodEntry(this.getClass(), "getReferenceCategory");

        return "Secret Question";
    }

    @Override
    public boolean isConfigurable() {
        LoggerUtils.markMethodEntry(this.getClass(), "isConfigurable");

        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        LoggerUtils.markMethodEntry(this.getClass(), "getRequirementChoices");

        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        LoggerUtils.markMethodEntry(this.getClass(), "isUserSetupAllowed");

        return true;
    }

    @Override
    public String getHelpText() {
        LoggerUtils.markMethodEntry(this.getClass(), "getHelpText");

        return "A secret question that a user has to answer. i.e. What is your mother's maiden name.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        LoggerUtils.markMethodEntry(this.getClass(), "getConfigProperties");

        return CONFIG_PROPERTIES;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
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

        return PROVIDER_ID;
    }
}
