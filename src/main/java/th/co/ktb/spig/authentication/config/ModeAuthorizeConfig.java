package th.co.ktb.spig.authentication.config;

import th.co.ktb.spig.authentication.entity.AuthorizeConfig;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@ConfigurationProperties()
@Component
@Data
public class ModeAuthorizeConfig {

    private Map<String, AuthorizeConfig> modeAuthorize = new HashMap<String, AuthorizeConfig>();

}
