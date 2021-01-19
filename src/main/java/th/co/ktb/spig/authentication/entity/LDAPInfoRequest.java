package th.co.ktb.spig.authentication.entity;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class LDAPInfoRequest {

    @NotBlank
    @ApiModelProperty(position = 1, required = true, dataType = "String", example = "user", notes = "LDAP Username")
    private String username;

    @NotBlank
    @ApiModelProperty(position = 2, required = true, dataType = "String", example = "password", notes = "LDAP Password")
    private String password;

    @NotBlank
    @ApiModelProperty(position = 3, required = true, dataType = "String", example = "esolution", notes = "Service")
    private String service;

    @ApiModelProperty(position = 3, required = false, dataType = "String", example = "61cf23c7-0bd6-4201-b4de-dccd05cb25c6", notes = "Device UUID")
    private String uuid;

    @ApiModelProperty(position = 4, required = false, dataType = "String", example = "force", notes = "login mode (force, authorize)")
    @Pattern(regexp = "force|authorize")
    private String mode;

    @ApiModelProperty(position = 5, required = false, dataType = "String", example = "A2087", notes = "Overwritten BranchCode for 'authorize' mode only")
    private String branchCode;

    public enum loginMode {
        force,
        authorize
    }

}
