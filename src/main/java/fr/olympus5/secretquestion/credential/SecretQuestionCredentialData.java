package fr.olympus5.secretquestion.credential;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class SecretQuestionCredentialData {
    private final String question;

    @JsonCreator
    public SecretQuestionCredentialData(@JsonProperty("question") String question) {
        this.question = question;
    }

    public String getQuestion() {
        return this.question;
    }
}
