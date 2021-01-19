package th.co.ktb.spig.authentication.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class KeycloakCredentials {
    private String type;
    private String value;

    @JsonProperty("type")
    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    @JsonProperty("value")
    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
