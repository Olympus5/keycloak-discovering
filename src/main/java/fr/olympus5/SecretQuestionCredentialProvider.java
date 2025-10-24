package fr.olympus5;

import org.keycloak.common.util.Time;
import org.keycloak.credential.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;

public class SecretQuestionCredentialProvider implements CredentialProvider<SecretQuestionCredentialModel>, CredentialInputValidator {
    private final KeycloakSession session;

    public SecretQuestionCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public CredentialModel createCredential(RealmModel realmModel, UserModel userModel, SecretQuestionCredentialModel secretQuestionCredentialModel) {
        LoggerUtils.markMethodEntry(this.getClass(), "createCredential");

        if (secretQuestionCredentialModel.getCreatedDate() == null) {
            secretQuestionCredentialModel.setCreatedDate(Time.currentTimeMillis());
        }

        return userModel.credentialManager().createStoredCredential(secretQuestionCredentialModel);
    }

    @Override
    public boolean deleteCredential(RealmModel realmModel, UserModel userModel, String credentialId) {
        LoggerUtils.markMethodEntry(this.getClass(), "deleteCredential");

        return userModel.credentialManager().removeStoredCredentialById(credentialId);
    }

    @Override
    public boolean isValid(RealmModel realmModel, UserModel userModel, CredentialInput credentialInput) {
        LoggerUtils.markMethodEntry(this.getClass(), "isValid");

        if (!(credentialInput instanceof UserCredentialModel)) {
            return false;
        }

        if (!credentialInput.getType().equals(this.getType())) {
            return false;
        }

        String challengeResponse = credentialInput.getChallengeResponse();
        if (challengeResponse == null) {
            return false;
        }

        CredentialModel credentialModel = userModel.credentialManager().getStoredCredentialById(credentialInput.getCredentialId());
        SecretQuestionCredentialModel sqcm = this.getCredentialFromModel(credentialModel);

        return sqcm.getSecretQuestionSecretData().getAnswer().equals(challengeResponse);
    }

    @Override
    public SecretQuestionCredentialModel getCredentialFromModel(CredentialModel credentialModel) {
        LoggerUtils.markMethodEntry(this.getClass(), "getCredentialFromModel");

        return SecretQuestionCredentialModel.createFromCredentialModel(credentialModel);
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext credentialTypeMetadataContext) {
        LoggerUtils.markMethodEntry(this.getClass(), "getCredentialTypeMetadata");

        return CredentialTypeMetadata.builder()
                .type(this.getType())
                .category(CredentialTypeMetadata.Category.TWO_FACTOR)
                .displayName(SecretQuestionCredentialProviderFactory.PROVIDER_ID)
                .helpText("secret-question-text")
                .createAction(SecretQuestionAuthenticatorFactory.PROVIDER_ID)
                .removeable(false)
                .build(this.session);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realmModel, UserModel userModel, String credentialType) {
        LoggerUtils.markMethodEntry(this.getClass(), "isConfiguredFor");

        if (!this.supportsCredentialType(this.getType())) {
            return false;
        }

        return !userModel.credentialManager().getStoredCredentialsByTypeStream(credentialType).findAny().isPresent();
    }

    @Override
    public boolean supportsCredentialType(String type) {
        LoggerUtils.markMethodEntry(this.getClass(), "supportsCredentialType");

        return this.getType().equals(type);
    }

    @Override
    public String getType() {
        LoggerUtils.markMethodEntry(this.getClass(), "getType");

        return SecretQuestionCredentialModel.TYPE;
    }


}
