package fr.olympus5.secretquestion.credential;

import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

public class SecretQuestionCredentialModel extends CredentialModel {
    public static final String TYPE = "SECRET_QUESTION";

    private final SecretQuestionCredentialData credentialData;
    private final SecretQuestionSecretData secretData;

    private SecretQuestionCredentialModel(SecretQuestionCredentialData credentialData, SecretQuestionSecretData secretData) {
        this.credentialData = credentialData;
        this.secretData = secretData;
    }

    private SecretQuestionCredentialModel(String question, String answer) {
        this.credentialData = new SecretQuestionCredentialData(question);
        this.secretData = new SecretQuestionSecretData(answer);
    }

    public static SecretQuestionCredentialModel createFromCredentialModel(CredentialModel credentialModel) {
        try {
            SecretQuestionCredentialData credentialData = JsonSerialization.readValue(credentialModel.getCredentialData(), SecretQuestionCredentialData.class);
            SecretQuestionSecretData secretData = JsonSerialization.readValue(credentialModel.getSecretData(), SecretQuestionSecretData.class);

            SecretQuestionCredentialModel secretQuestionCredentialModel = new SecretQuestionCredentialModel(credentialData, secretData);
            secretQuestionCredentialModel.setUserLabel(credentialModel.getUserLabel());
            secretQuestionCredentialModel.setCreatedDate(credentialModel.getCreatedDate());
            secretQuestionCredentialModel.setType(TYPE);
            secretQuestionCredentialModel.setId(credentialModel.getId());
            secretQuestionCredentialModel.setSecretData(credentialModel.getSecretData());
            secretQuestionCredentialModel.setCredentialData(credentialModel.getCredentialData());

            return secretQuestionCredentialModel;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static SecretQuestionCredentialModel createSecretQuestion(String question, String answer) {
        SecretQuestionCredentialModel secretQuestionCredentialModel = new SecretQuestionCredentialModel(question, answer);
        secretQuestionCredentialModel.fillCredentialModelFields();
        return secretQuestionCredentialModel;
    }

    private void fillCredentialModelFields() {
        try {
            this.setCredentialData(JsonSerialization.writeValueAsPrettyString(this.credentialData));
            this.setSecretData(JsonSerialization.writeValueAsPrettyString(this.secretData));
            this.setType(TYPE);
            this.setCreatedDate(Time.currentTimeMillis());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public SecretQuestionCredentialData getSecretQuestionCredentialData() {
        return this.credentialData;
    }

    public SecretQuestionSecretData getSecretQuestionSecretData() {
        return this.secretData;
    }
}
