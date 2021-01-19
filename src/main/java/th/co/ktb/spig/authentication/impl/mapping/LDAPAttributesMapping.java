package th.co.ktb.spig.authentication.impl.mapping;

import org.json.JSONObject;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class LDAPAttributesMapping {

    public JSONObject convertAttributes2JSON(Map<String,String> attributesMapping){
        JSONObject response = new JSONObject(attributesMapping);
        return response;
    }
}
