package th.co.ktb.spig.authentication.entity;

import lombok.Data;

import java.util.List;

@Data
public class RealmConfig {

    private String url;
    private String method;
    private List<String> ldapAttributeMapping;
    private String eventCallback;
    private Boolean checkConcurrentLogin;
    private String auditRealm;
    private String auditUrl;
    private String role;
    private List<String> overwriteAttributes;



}
