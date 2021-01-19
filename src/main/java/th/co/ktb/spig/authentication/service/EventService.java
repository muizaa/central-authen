package th.co.ktb.spig.authentication.service;

import th.co.ktb.spig.authentication.config.UserServiceConfig;
import th.co.ktb.spig.authentication.constant.AuthEventType;
import th.co.ktb.spig.authentication.entity.AuthEvent;
import th.co.ktb.spig.authentication.entity.AuthEventBody;
import th.co.ktb.spig.authentication.entity.RealmConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class EventService {

    private final UserServiceConfig userServiceConfig;

    private final RestTemplate restTemplate;

    @Async("taskExecutor")
    public void publishSessionClearedEvent(String service, String sessionId, String authToken) {
        AuthEvent authEvent = AuthEvent.builder()
                .type(AuthEventType.SESSION_CLEARED)
                .uri(String.format("/session/%s", sessionId))
                .body(AuthEventBody.builder().code(AuthEventType.SESSION_CLEARED.name()).build())
                .build();

        publishEvent(service, authEvent, authToken);
    }

    private void publishEvent(String service, AuthEvent authEvent, String authToken) {

        RealmConfig serviceConfig = userServiceConfig.getUserService().get(service);

        if (serviceConfig != null && StringUtils.isNotBlank(serviceConfig.getEventCallback())) {

            String callbackURL = serviceConfig.getEventCallback() + authEvent.getUri();
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(authToken);
            HttpEntity<AuthEventBody> authEventBodyHttpEntity = new HttpEntity<>(authEvent.getBody(), headers);
            try {
                log.info("Publish event to {}", callbackURL);
                restTemplate.exchange(callbackURL, HttpMethod.POST, authEventBodyHttpEntity, String.class);
            } catch (Exception e) {
                log.error("Error sending event", e);
            }


        }

    }

}
