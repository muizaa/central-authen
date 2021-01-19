package th.co.ktb.spig.authentication.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ibm.th.microservice.framework.exceptionhandler.model.BusinessProcessingException;
import com.ibm.th.microservice.framework.exceptionhandler.model.BusinessProcessingTimeoutException;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.client.HttpServerErrorException;
import th.co.ktb.spig.authentication.config.UserServiceConfig;
import th.co.ktb.spig.authentication.constant.ErrorMessageConstant;
import th.co.ktb.spig.authentication.entity.RealmConfig;
import th.co.ktb.spig.authentication.entity.UserRolesResponse;
import th.co.ktb.spig.authentication.exception.UnauthorizedException;
import com.ibm.th.microservice.framework.exceptionhandler.model.ErrorInfo;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import th.co.ktb.spig.authentication.util.KeycloakUtil;

@Service
public class UserServiceClient {

    private static final Logger log = LoggerFactory.getLogger(UserServiceClient.class);

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private UserServiceConfig userServiceConfig;

    public UserRolesResponse getUserRoles(String service, String token, JSONObject userProfile) throws JsonProcessingException {

        if (userServiceConfig.getUserService().containsKey(service)) {

            try {

                HttpHeaders headers = new HttpHeaders();
                headers.setBearerAuth(token);
                headers.setContentType(MediaType.APPLICATION_JSON);
                HttpEntity<String> request = new HttpEntity<>(userProfile != null ? userProfile.toString() : StringUtils.EMPTY, headers);
                RealmConfig realmConfig = userServiceConfig.getUserService().get(service);
                log.debug("Calling User-Service: {}, {}", service, realmConfig.getUrl());

                ResponseEntity<UserRolesResponse> roles = restTemplate.exchange(realmConfig.getUrl(),
                        HttpMethod.POST,
                        request,
                        UserRolesResponse.class);

                return roles.getBody();

            }catch (HttpServerErrorException | HttpClientErrorException e){
                log.error("Error while calling user-service of '{}'",service);
                log.error(String.format("%s - %s",e.getMessage(),e.getResponseBodyAsString()),e);
                JSONObject errors;
                if(e.getResponseBodyAsString().isEmpty()){
                    errors = new JSONObject();
                }else {
                    errors = new JSONObject(e.getResponseBodyAsString());
                }

                if(errors.has("errors")){
                    ErrorInfo errorInfo = new ObjectMapper().readValue(errors.getJSONArray("errors").getJSONObject(0).toString(), ErrorInfo.class);
                    throw new UnauthorizedException(errorInfo.getCode(),
                            errorInfo.getMessage(),
                            String.format(ErrorMessageConstant.USER_SERVICE_BAD_REQUEST_ERROR_DESC, service),
                            e.getStatusCode().toString(),
                            e.getResponseBodyAsString());
                }else {
                    throw new UnauthorizedException(ErrorMessageConstant.USER_SERVICE_BAD_REQUEST_ERROR_CODE,
                            ErrorMessageConstant.USER_SERVICE_BAD_REQUEST_ERROR_INFO,
                            String.format(ErrorMessageConstant.USER_SERVICE_BAD_REQUEST_ERROR_DESC, service),
                            e.getStatusCode().toString(),
                            e.getResponseBodyAsString());
                }
            }
        }
        return null;
    }

    public boolean isUserServiceEnable(String service){
        boolean enable = userServiceConfig.getUserService().containsKey(service);
        if( enable){
            enable = userServiceConfig.getUserService().get(service).getUrl() != null;
        }
        return enable;
    }

}
