package th.co.ktb.spig.authentication.entity;

import io.swagger.annotations.ApiModelProperty;
import lombok.Data;
import org.json.JSONObject;

import javax.validation.constraints.NotBlank;
import java.util.Map;

@Data
public class ExchangeTokenRequest {

    @NotBlank
    @ApiModelProperty(position = 1, required = true, dataType = "String", example = "xxxx", notes = "Refresh Token")
    private String refreshToken;

    @ApiModelProperty(position = 2, required = true, dataType = "String", example = "{\"aa\": \"bb\"}", notes = "Exchange Attributes Object")
    private Map<String, String> attributes;

    @NotBlank
    @ApiModelProperty(position = 3, required = true, dataType = "String", example = "esolution", notes = "Service")
    private String service;

    @ApiModelProperty(position = 4, required = true, dataType = "String", example = "61cf23c7-0bd6-4201-b4de-dccd05cb25c6", notes = "Device UUID")
    private String uuid;

}
