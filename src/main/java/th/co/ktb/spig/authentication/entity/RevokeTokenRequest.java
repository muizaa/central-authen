package th.co.ktb.spig.authentication.entity;

import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
public class RevokeTokenRequest {

    @NotBlank
    @ApiModelProperty(position = 1, required = true, dataType = "String", example = "xxxx", notes = "Access Token")
    private String accessToken;

    @ApiModelProperty(position = 2, required = true, dataType = "String", example = "TIMEOUT", notes = "Audit Event Type")
    private String eventType;

    @NotBlank
    @ApiModelProperty(position = 3, required = true, dataType = "String", example = "esolution", notes = "Service")
    private String service;

    @ApiModelProperty(position = 4, required = true, dataType = "String", example = "61cf23c7-0bd6-4201-b4de-dccd05cb25c6", notes = "Device UUID")
    private String uuid;

}
