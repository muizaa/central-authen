package th.co.ktb.spig.authentication.entity;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthenticationTokenResponse {

    @ApiModelProperty(position = 1, required = true, dataType = "String", example = "xxxx", notes = "Access Token - using for access the specific service of the project under SPIG. This token has a shortage lifetime and cannot be reused for other projects and environments.")
    private String accessToken;

    @ApiModelProperty(position = 2, required = true, dataType = "String", example = "xxxx", notes = "Refresh Token - using for extend the lifetime of access token. This token has to be used with refreshToken API.")
    private String refreshToken;

    @ApiModelProperty(position = 3, required = true, dataType = "String", example = "1beec2bd-7329-48e6-ae56-cddb92314fdb", notes = "Session UUID - the session id from KeyCloak")
    private String sessionState;

}
