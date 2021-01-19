package th.co.ktb.spig.authentication.config;

import th.co.ktb.spig.authentication.entity.RealmConfig;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@ConfigurationProperties()
@Component
@Data
public class UserServiceConfig {

    private Map<String, RealmConfig> userService = new HashMap<>();

}
