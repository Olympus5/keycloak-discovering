package fr.olympus5.externalauth.authentication;

import fr.olympus5.LoggerUtils;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class ExternalApplicationAuthenticatorFactory implements AuthenticatorFactory {

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    public static final String CONFIG_APPLICATION_ID = "application-id";
    public static final String CONFIG_EXTERNAL_APP_URL = "external-application-url";
    public static final String ID = "external-application-authenticator";

    @Override
    public String getDisplayType() {
        LoggerUtils.markMethodEntry(this.getClass(), "getDisplayType");

        return "External Application Authenticator";
    }

    @Override
    public String getReferenceCategory() {
        LoggerUtils.markMethodEntry(this.getClass(), "getReferenceCategory");

        return null;
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

        return false;
    }

    @Override
    public String getHelpText() {
        LoggerUtils.markMethodEntry(this.getClass(), "getHelpText");

        return "External Application Authenticator";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        LoggerUtils.markMethodEntry(this.getClass(), "getConfigProperties");

        ProviderConfigProperty property1 = new ProviderConfigProperty(CONFIG_APPLICATION_ID, "Application ID",
                "Application ID sent in the token.", ProviderConfigProperty.STRING_TYPE,
                ExternalApplicationAuthenticator.DEFAULT_APPLICATION_ID);

        ProviderConfigProperty property2 = new ProviderConfigProperty(CONFIG_EXTERNAL_APP_URL, "External Application URL",
                "URL of the application to redirect to. It has to contain token position marked with \"{TOKEN}\" (without quotes).",
                ProviderConfigProperty.STRING_TYPE, ExternalApplicationAuthenticator.DEFAULT_EXTERNAL_APP_URL);

        return List.of(property1, property2);
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        LoggerUtils.markMethodEntry(this.getClass(), "create");

        return new ExternalApplicationAuthenticator();
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

        return ID;
    }
}
