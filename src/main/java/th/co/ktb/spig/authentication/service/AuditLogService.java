package th.co.ktb.spig.authentication.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import th.co.ktb.spig.authentication.config.UserServiceConfig;
import th.co.ktb.spig.authentication.constant.AuthEventType;
import th.co.ktb.spig.authentication.entity.AuthEvent;
import th.co.ktb.spig.authentication.entity.AuthEventBody;
import th.co.ktb.spig.authentication.entity.RealmConfig;
import th.co.ktb.spig.authentication.repository.entity.AuditLog;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuditLogService {

    private final RestTemplate restTemplate;

    private final UserServiceConfig userServiceConfig;

    @Async("taskExecutor")
    public void add(AuditLog auditLog, String service, String authToken) {
        RealmConfig serviceConfig = userServiceConfig.getUserService().get(service);

        if (serviceConfig != null && StringUtils.isNotBlank(serviceConfig.getAuditUrl())) {

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(authToken);
            HttpEntity<AuditLog> auditLogHttpEntity = new HttpEntity<>(auditLog, headers);
            try {
                log.info("Publish audit log to {}", serviceConfig.getAuditUrl());
                restTemplate.exchange(serviceConfig.getAuditUrl(), HttpMethod.POST, auditLogHttpEntity, String.class);
            } catch (Exception e) {
                log.error("Error while publish audit log - {}", e.getMessage());
            }
        }

    }

}
