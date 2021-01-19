package th.co.ktb.spig.authentication.entity;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthEventBody {
    private String code;
}
