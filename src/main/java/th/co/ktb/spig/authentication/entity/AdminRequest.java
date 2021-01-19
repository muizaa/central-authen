package th.co.ktb.spig.authentication.entity;

import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
public class AdminRequest {

    private String command;
    private String password;
    private String service;

}
