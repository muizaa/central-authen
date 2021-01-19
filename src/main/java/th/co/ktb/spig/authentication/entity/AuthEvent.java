package th.co.ktb.spig.authentication.entity;

import th.co.ktb.spig.authentication.constant.AuthEventType;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthEvent {
    private AuthEventType type;
    private String uri;
    private AuthEventBody body;
}
