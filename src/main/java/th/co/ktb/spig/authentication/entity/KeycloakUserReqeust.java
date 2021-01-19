package th.co.ktb.spig.authentication.entity;

import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class KeycloakUserReqeust {

    private String username;

    private String enabled;

    private List<KeycloakCredentials> credentials;

    private Map<String, String> attributes;

}
