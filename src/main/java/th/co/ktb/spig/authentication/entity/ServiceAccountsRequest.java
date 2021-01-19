package th.co.ktb.spig.authentication.entity;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ServiceAccountsRequest {

    @NotBlank
    @ApiModelProperty(position = 1, required = true, dataType = "String", example = "idp", notes = "Client ID from Keycloak")

    private String clientId;

    @NotBlank
    @ApiModelProperty(position = 2, required = true, dataType = "String", example = "e3faj852-b736-39d4-809b-a4a5b91a560d", notes = "Client Secret from Keycloak")
    private String clientSecret;

    @NotBlank
    @ApiModelProperty(position = 3, required = true, dataType = "String", example = "esolution", notes = "Service")
    private String service;

    @ApiModelProperty(position = 4, required = true, dataType = "String", example = "61cf23c7-0bd6-4201-b4de-dccd05cb25c6", notes = "Device UUID")
    private String uuid;

}
