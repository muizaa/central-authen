package th.co.ktb.spig.authentication.external;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import th.co.ktb.spig.authentication.constant.CommonConstant;
import th.co.ktb.spig.authentication.constant.ErrorMessageConstant;
import th.co.ktb.spig.authentication.entity.KeycloakAttributes;
import th.co.ktb.spig.authentication.entity.KeycloakRole;
import th.co.ktb.spig.authentication.entity.KeycloakSession;
import th.co.ktb.spig.authentication.entity.KeycloakTokenResponse;
import th.co.ktb.spig.authentication.util.KeycloakUtil;
import com.ibm.th.microservice.framework.exceptionhandler.model.BusinessProcessingException;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;


@Component
public class KeycloakRestTemplate {
    private final Logger log = LoggerFactory.getLogger(KeycloakRestTemplate.class);

    @Autowired
    private RestTemplate restTemplate;

    @Value("${keycloak.url}")
    private String keycloakURL;

    private HttpHeaders prepareHeaders(String tokenBearer) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", String.format(CommonConstant.BEARER_TOKEN, tokenBearer));
        return headers;
    }

    private HttpHeaders prepareHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        return headers;
    }

    public HttpEntity<String> handleEntity(Object request, String tokenBearer) {
        HttpEntity<String> entity = null;
        ObjectMapper mapper = new ObjectMapper();
        try {
            log.debug("Mapping body message: {}", request);
            entity = new HttpEntity<>(mapper.writeValueAsString(request), prepareHeaders(tokenBearer));
        } catch (JsonProcessingException e) {
            log.error(e.getMessage(),e);
        }
        return entity;
    }

    public HttpEntity<MultiValueMap<String, String>> handleEntity(MultiValueMap<String, String> map) {
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(map, prepareHeaders());
        return entity;
    }

    public HttpEntity<String> handleEntity(String tokenBearer) {
        HttpEntity<String> entity = new HttpEntity<>(prepareHeaders(tokenBearer));
        return entity;
    }

    public KeycloakTokenResponse generateNewToken(HttpEntity<MultiValueMap<String, String>> entity, String realm) {
        KeycloakTokenResponse response = null;
        String finalURL = String.format(CommonConstant.KEYCLOAK_GENERATE_TOKEN_ENDPOINT, keycloakURL, realm);
        log.debug(String.format("Calling Keycloak: %s", finalURL));
        try {
            ResponseEntity<String> responseEntity = restTemplate.exchange(finalURL, HttpMethod.POST, entity, String.class);
            response = new ObjectMapper().readValue(responseEntity.getBody(), KeycloakTokenResponse.class);
        } catch (HttpStatusCodeException e) {
            log.error(e.getResponseBodyAsString(),e);
            throw new BusinessProcessingException(ErrorMessageConstant.KEYCLOAK_ERROR_GENERATE_TOKEN_CODE,
                    ErrorMessageConstant.KEYCLOAK_ERROR_GENERATE_TOKEN_INFO,
                    String.format(ErrorMessageConstant.KEYCLOAK_ERROR_GENERATE_TOKEN_DESC,e.getMessage(), finalURL),
                    KeycloakUtil.getKeyCloakErrorCode(e),
                    KeycloakUtil.getKeyCloakErrorDescription(e));
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new BusinessProcessingException(ErrorMessageConstant.KEYCLOAK_ERROR_GENERATE_TOKEN_CODE,
                    ErrorMessageConstant.KEYCLOAK_ERROR_GENERATE_TOKEN_INFO,
                    String.format(ErrorMessageConstant.KEYCLOAK_ERROR_GENERATE_TOKEN_DESC,e.getMessage(), finalURL));
        }
        return response;
    }

    public String getUserIDByUsername(HttpEntity<String> entity, String username, String realm) {
        String response = null;
        String finalURL = String.format(CommonConstant.KEYCLOAK_GET_USERINFO_ENDPOINT, keycloakURL, realm, username);
        log.debug(String.format("Calling Keycloak: %s", finalURL));
        try {
            ResponseEntity<String> responseEntity = restTemplate.exchange(finalURL, HttpMethod.GET, entity, String.class);
            JSONArray jsonArray = new JSONArray(responseEntity.getBody());
            for (int index = 0; index < jsonArray.length(); index++) {
                JSONObject jsonObject = jsonArray.getJSONObject(index);
                if (jsonObject.getString("username").equalsIgnoreCase(username)) {
                    response = jsonObject.getString("id");
                    break;
                }
            }
        } catch (HttpStatusCodeException e) {
            log.error(e.getResponseBodyAsString(),e);
            throw new BusinessProcessingException(ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_USER_CODE,
                    ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_USER_INFO,
                    String.format(ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_USER_DESC,e.getMessage(), finalURL),
                    KeycloakUtil.getKeyCloakErrorCode(e),
                    KeycloakUtil.getKeyCloakErrorDescription(e));
        }
        return response;
    }

    public boolean createUser(HttpEntity<String> entity, String realm) {
        boolean response = false;
        String finalURL = String.format(CommonConstant.KEYCLOAK_CREATE_USER_ENDPOINT, keycloakURL, realm);
        log.debug(String.format("Calling Keycloak: %s", finalURL));
        try {
            ResponseEntity<String> responseEntity = restTemplate.exchange(finalURL, HttpMethod.POST, entity, String.class);
            response = responseEntity.getStatusCode() == HttpStatus.CREATED;
        } catch (HttpStatusCodeException e) {
            log.error(e.getResponseBodyAsString(),e);
            throw new BusinessProcessingException(ErrorMessageConstant.KEYCLOAK_ERROR_CREATE_USERINFO_CODE,
                    ErrorMessageConstant.KEYCLOAK_ERROR_CREATE_USERINFO_INFO,
                    String.format(ErrorMessageConstant.KEYCLOAK_ERROR_CREATE_USERINFO_DESC,e.getMessage(), finalURL),
                    KeycloakUtil.getKeyCloakErrorCode(e),
                    KeycloakUtil.getKeyCloakErrorDescription(e));
        }
        return response;
    }

    public boolean logoutUser(HttpEntity<String> entity, String userid, String realm) {
        boolean response = false;
        String finalURL = String.format(CommonConstant.KEYCLOAK_LOGOUT_USER_ENDPOINT, keycloakURL, realm, userid);
        log.debug(String.format("Calling Keycloak: %s", finalURL));
        try {
            ResponseEntity<String> responseEntity = restTemplate.exchange(finalURL, HttpMethod.POST, entity, String.class);
            response = responseEntity.getStatusCode() == HttpStatus.NO_CONTENT;
        } catch (HttpStatusCodeException e) {
            log.error(e.getResponseBodyAsString(),e);
            throw new BusinessProcessingException(ErrorMessageConstant.KEYCLOAK_ERROR_LOGOUT_USER_CODE,
                    ErrorMessageConstant.KEYCLOAK_ERROR_LOGOUT_USER_INFO,
                    String.format(ErrorMessageConstant.KEYCLOAK_ERROR_LOGOUT_USER_DESC,e.getMessage(), finalURL),
                    KeycloakUtil.getKeyCloakErrorCode(e),
                    KeycloakUtil.getKeyCloakErrorDescription(e));
        }
        return response;
    }

    public boolean resetPassword(HttpEntity<String> entity, String userid, String realm) {
        boolean response = false;
        String finalURL = String.format(CommonConstant.KEYCLOAK_RESET_PASSWORD_USER_ENDPOINT, keycloakURL, realm, userid);
        log.debug(String.format("Calling Keycloak: %s", finalURL));
        try {
            ResponseEntity<String> responseEntity = restTemplate.exchange(finalURL, HttpMethod.PUT, entity, String.class);
            response = responseEntity.getStatusCode() == HttpStatus.NO_CONTENT;
        } catch (HttpStatusCodeException e) {
            log.error(e.getMessage(),e);
            throw new BusinessProcessingException(ErrorMessageConstant.KEYCLOAK_ERROR_RESET_PASSWORD_CODE,
                    ErrorMessageConstant.KEYCLOAK_ERROR_RESET_PASSWORD_INFO,
                    String.format(ErrorMessageConstant.KEYCLOAK_ERROR_RESET_PASSWORD_DESC,e.getMessage(), finalURL),
                    KeycloakUtil.getKeyCloakErrorCode(e),
                    KeycloakUtil.getKeyCloakErrorDescription(e));
        }
        return response;
    }

    public List<KeycloakRole> getRole(HttpEntity<String> entity, String realm) {
        List<KeycloakRole> response = null;
        String finalURL = String.format(CommonConstant.KEYCLOAK_GET_ROLE_ENDPOINT, keycloakURL, realm);
        log.debug(String.format("Calling Keycloak: %s", finalURL));
        try {
            ResponseEntity<List<KeycloakRole>> responseEntity = restTemplate.exchange(finalURL, HttpMethod.GET, entity, new ParameterizedTypeReference<List<KeycloakRole>>() {
            });
            response = responseEntity.getBody();
        } catch (HttpStatusCodeException e) {
            log.error(e.getResponseBodyAsString(),e);
            throw new BusinessProcessingException(ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_ROLE_CODE,
                    ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_ROLE_INFO,
                    String.format(ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_ROLE_DESC,e.getMessage(), finalURL),
                    KeycloakUtil.getKeyCloakErrorCode(e),
                    KeycloakUtil.getKeyCloakErrorDescription(e));
        }
        return response;
    }

    public boolean deleteUserRole(HttpEntity<String> entity, String userid, String realm) {
        boolean response;
        String finalURL = String.format(CommonConstant.KEYCLOAK_USER_ROLE_MAPPING_ENDPOINT, keycloakURL, realm, userid);
        log.debug(String.format("Calling Keycloak: %s", finalURL));
        try {
            ResponseEntity<String> responseEntity = restTemplate.exchange(finalURL, HttpMethod.DELETE, entity, String.class);
            response = responseEntity.getStatusCode() == HttpStatus.NO_CONTENT;
        } catch (HttpStatusCodeException e) {
            log.error(e.getResponseBodyAsString(),e);
            throw new BusinessProcessingException(ErrorMessageConstant.KEYCLOAK_ERROR_REMOVE_USER_ROLE_CODE,
                    ErrorMessageConstant.KEYCLOAK_ERROR_REMOVE_USER_ROLE_INFO,
                    String.format(ErrorMessageConstant.KEYCLOAK_ERROR_REMOVE_USER_ROLE_DESC,e.getMessage(), finalURL),
                    KeycloakUtil.getKeyCloakErrorCode(e),
                    KeycloakUtil.getKeyCloakErrorDescription(e));
        }
        return response;
    }

    public boolean updateUserRoleMapping(HttpEntity<String> entity, String userid, String realm) {
        boolean response;
        String finalURL = String.format(CommonConstant.KEYCLOAK_USER_ROLE_MAPPING_ENDPOINT, keycloakURL, realm, userid);
        log.debug(String.format("Calling Keycloak: %s", finalURL));
        try {
            ResponseEntity<String> responseEntity = restTemplate.exchange(finalURL, HttpMethod.POST, entity, String.class);
            response = responseEntity.getStatusCode() == HttpStatus.NO_CONTENT;
        } catch (HttpStatusCodeException e) {
            log.error(e.getResponseBodyAsString(),e);
            throw new BusinessProcessingException(ErrorMessageConstant.KEYCLOAK_ERROR_UPDATE_USER_ROLE_CODE,
                    ErrorMessageConstant.KEYCLOAK_ERROR_UPDATE_USER_ROLE_INFO,
                    String.format(ErrorMessageConstant.KEYCLOAK_ERROR_UPDATE_USER_ROLE_DESC,e.getMessage(), finalURL),
                    KeycloakUtil.getKeyCloakErrorCode(e),
                    KeycloakUtil.getKeyCloakErrorDescription(e));
        }
        return response;
    }

    public List<KeycloakRole> getUserRoleMapping(HttpEntity<String> entity, String userid, String realm) {
        List<KeycloakRole> response = new ArrayList<>();
        String finalURL = String.format(CommonConstant.KEYCLOAK_USER_ROLE_MAPPING_ASSIGNED_ENDPOINT, keycloakURL, realm, userid);
        log.debug(String.format("Calling Keycloak: %s", finalURL));
        try {
            ResponseEntity<String> responseEntity = restTemplate.exchange(finalURL, HttpMethod.GET, entity, String.class);
            JSONArray jsonArray = new JSONArray(responseEntity.getBody());
            for (int index = 0; index < jsonArray.length(); index++) {
                JSONObject jsonObject = jsonArray.getJSONObject(index);
                response.add(new ObjectMapper().readValue(jsonObject.toString(), KeycloakRole.class));
            }
        } catch (HttpStatusCodeException e) {
            log.error(e.getMessage(),e);
            throw new BusinessProcessingException(ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_USER_ROLE_CODE,
                    ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_USER_ROLE_INFO,
                    String.format(ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_USER_ROLE_DESC,e.getMessage(), finalURL),
                    KeycloakUtil.getKeyCloakErrorCode(e),
                    KeycloakUtil.getKeyCloakErrorDescription(e));
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new BusinessProcessingException(ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_USER_ROLE_CODE,
                    ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_USER_ROLE_INFO,
                    String.format(ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_USER_ROLE_DESC,e.getMessage(), finalURL));
        }
        return response;
    }

    public List<KeycloakSession> getUserSessionsByUserID(HttpEntity<String> entity, String username, String realm) {
        List<KeycloakSession> response = new ArrayList<>();
        String finalURL = String.format(CommonConstant.KEYCLOAK_GET_USER_SESSIONS_ENDPOINT, keycloakURL, realm, username);
        log.debug(String.format("Calling Keycloak: %s", finalURL));
        try {
            ResponseEntity<String> responseEntity = restTemplate.exchange(finalURL, HttpMethod.GET, entity, String.class);
            JSONArray jsonArray = new JSONArray(responseEntity.getBody());
            for (int index = 0; index < jsonArray.length(); index++) {
                JSONObject jsonObject = jsonArray.getJSONObject(index);
                response.add(new ObjectMapper().readValue(jsonObject.toString(), KeycloakSession.class));
            }
        } catch (HttpStatusCodeException e) {
            log.error(e.getResponseBodyAsString(),e);
            throw new BusinessProcessingException(ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_USER_SESSION_CODE,
                    ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_USER_SESSION_INFO,
                    String.format(ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_USER_SESSION_DESC,e.getMessage(), finalURL),
                    KeycloakUtil.getKeyCloakErrorCode(e),
                    KeycloakUtil.getKeyCloakErrorDescription(e));
        }catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new BusinessProcessingException(ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_USER_SESSION_CODE,
                    ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_USER_SESSION_INFO,
                    String.format(ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_USER_SESSION_DESC,e.getMessage(), finalURL));

        }
        return response;
    }

    public boolean logoutSession(HttpEntity<String> entity, String sessionid, String realm) {
        boolean response = false;
        String finalURL = String.format(CommonConstant.KEYCLOAK_LOGOUT_SESSION_ENDPOINT, keycloakURL, realm, sessionid);
        log.debug(String.format("Calling Keycloak: %s", finalURL));
        try {
            ResponseEntity<String> responseEntity = restTemplate.exchange(finalURL, HttpMethod.DELETE, entity, String.class);
            response = responseEntity.getStatusCode() == HttpStatus.NO_CONTENT;
        } catch (HttpStatusCodeException e) {
            log.error(e.getResponseBodyAsString(),e);
            throw new BusinessProcessingException(ErrorMessageConstant.KEYCLOAK_ERROR_LOGOUT_USER_SESSION_CODE,
                    ErrorMessageConstant.KEYCLOAK_ERROR_LOGOUT_USER_SESSION_INFO,
                    String.format(ErrorMessageConstant.KEYCLOAK_ERROR_LOGOUT_USER_SESSION_DESC,e.getMessage(), finalURL),
                    KeycloakUtil.getKeyCloakErrorCode(e),
                    KeycloakUtil.getKeyCloakErrorDescription(e));
        }
        return response;
    }

    public KeycloakAttributes getUserAttributes(HttpEntity<String> entity, String userid, String realm) {
        KeycloakAttributes response = null;
        String finalURL = String.format(CommonConstant.KEYCLOAK_USER_ATTRIBUTES_ENDPOINT, keycloakURL, realm, userid);
        log.debug(String.format("Calling Keycloak: %s", finalURL));
        try {
            ResponseEntity<String> responseEntity = restTemplate.exchange(finalURL, HttpMethod.GET, entity, String.class);
            JSONObject jsonObject = new JSONObject(responseEntity.getBody());
            if(jsonObject.has("attributes")) {
                response = new ObjectMapper().readValue(jsonObject.toString(), KeycloakAttributes.class);
            }else{
                response = new KeycloakAttributes();
                response.setAttributes(new HashMap<>());
            }
        } catch (HttpStatusCodeException e) {
            log.error(e.getResponseBodyAsString(),e);
            throw new BusinessProcessingException(ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_USERINFO_CODE,
                    ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_USERINFO_INFO,
                    String.format(ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_USERINFO_DESC,e.getMessage(), finalURL),
                    KeycloakUtil.getKeyCloakErrorCode(e),
                    KeycloakUtil.getKeyCloakErrorDescription(e));
        }catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new BusinessProcessingException(ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_USERINFO_CODE,
                    ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_USERINFO_INFO,
                    String.format(ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_USERINFO_DESC,e.getMessage(), finalURL));

        }
        return response;
    }

    public boolean updateUserAttributes(HttpEntity<String> entity, String userid, String realm) {
        boolean response = false;
        String finalURL = String.format(CommonConstant.KEYCLOAK_USER_ATTRIBUTES_ENDPOINT, keycloakURL, realm, userid);
        log.debug(String.format("Calling Keycloak: %s", finalURL));
        try {
            ResponseEntity<String> responseEntity = restTemplate.exchange(finalURL, HttpMethod.PUT, entity, String.class);
            response = responseEntity.getStatusCode() == HttpStatus.NO_CONTENT;
        } catch (HttpStatusCodeException e) {
            log.error(e.getResponseBodyAsString(),e);
            throw new BusinessProcessingException(ErrorMessageConstant.KEYCLOAK_ERROR_UPDATE_USERINFO_CODE,
                    ErrorMessageConstant.KEYCLOAK_ERROR_UPDATE_USERINFO_INFO,
                    String.format(ErrorMessageConstant.KEYCLOAK_ERROR_UPDATE_USERINFO_DESC,e.getMessage(), finalURL),
                    KeycloakUtil.getKeyCloakErrorCode(e),
                    KeycloakUtil.getKeyCloakErrorDescription(e));
        }
        return response;
    }

    public boolean validateAdminToken(HttpEntity<String> entity, String realm) {
        boolean response = false;
        String finalURL = String.format(CommonConstant.KEYCLOAK_GROUPS_COUNT_ENDPOINT, keycloakURL, realm);
        log.debug(String.format("Calling Keycloak: %s", finalURL));
        try {
            ResponseEntity<String> responseEntity = restTemplate.exchange(finalURL, HttpMethod.GET, entity, String.class);
            response = responseEntity.getStatusCode() == HttpStatus.OK;
        } catch (HttpStatusCodeException e) {
            log.error("Admin token validation is failed");
        }
        return response;
    }

    public boolean deleteUser(HttpEntity<String> entity, String userid, String realm) {
        boolean response = false;
        String finalURL = String.format(CommonConstant.KEYCLOAK_USER_ATTRIBUTES_ENDPOINT, keycloakURL, realm, userid);
        log.debug(String.format("Calling Keycloak: %s", finalURL));
        try {
            ResponseEntity<String> responseEntity = restTemplate.exchange(finalURL, HttpMethod.DELETE, entity, String.class);
            response = responseEntity.getStatusCode() == HttpStatus.NO_CONTENT;
        } catch (HttpStatusCodeException e) {
            log.error(e.getResponseBodyAsString(),e);
            throw new BusinessProcessingException(ErrorMessageConstant.KEYCLOAK_ERROR_DELETE_USERINFO_CODE,
                    ErrorMessageConstant.KEYCLOAK_ERROR_DELETE_USERINFO_INFO,
                    String.format(ErrorMessageConstant.KEYCLOAK_ERROR_DELETE_USERINFO_DESC,e.getMessage(), finalURL),
                    KeycloakUtil.getKeyCloakErrorCode(e),
                    KeycloakUtil.getKeyCloakErrorDescription(e));
        }
        return response;
    }

    public List<String> findAllUsers (HttpEntity<String> entity, String realm) {
        List<String> userids = new ArrayList<>();
        String finalURL = String.format(CommonConstant.KEYCLOAK_CREATE_USER_ENDPOINT, keycloakURL, realm);
        log.debug(String.format("Calling Keycloak: %s", finalURL));
        try {
            ResponseEntity<String> responseEntity = restTemplate.exchange(finalURL, HttpMethod.GET, entity, String.class);
            JSONArray jsonArray = new JSONArray(responseEntity.getBody());
            for (int index = 0; index < jsonArray.length(); index++) {
                JSONObject jsonObject = jsonArray.getJSONObject(index);
                userids.add(jsonObject.getString("id"));
            }
        } catch (HttpStatusCodeException e) {
            log.error(e.getResponseBodyAsString(),e);
            throw new BusinessProcessingException(ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_USER_CODE,
                    ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_USER_INFO,
                    String.format(ErrorMessageConstant.KEYCLOAK_ERROR_INQUIRE_USER_DESC,e.getMessage(), finalURL),
                    KeycloakUtil.getKeyCloakErrorCode(e),
                    KeycloakUtil.getKeyCloakErrorDescription(e));
        }
        return userids;
    }

}
