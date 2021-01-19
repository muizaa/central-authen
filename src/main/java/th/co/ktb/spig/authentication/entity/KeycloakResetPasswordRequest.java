package th.co.ktb.spig.authentication.entity;

import lombok.Data;

@Data
public class KeycloakResetPasswordRequest {

    private String type;
    private String value;

}
