package th.co.ktb.spig.authentication.entity;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import java.util.Map;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class KeycloakSession {

    private String id;
    private String username;
    private String userId;
    private String ipAddress;
    private Double start;
    private Double lastAccess;
    private Map<String, String> clients;

}
