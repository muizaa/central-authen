package th.co.ktb.spig.authentication.config;

import th.co.ktb.spig.authentication.service.LdapClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;

@Configuration
public class AppConfig {

    @Value("${ldap.urls}")
    private String ldapURLs;

    @Value("${ldap.base}")
    private String ldapBase;

    @Value("${ldap.binduser}")
    private String bindUser;

    @Value("${ldap.bindpassword}")
    private String bindPassword;

    @Bean
    public LdapContextSource contextSource() {
        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrls(ldapURLs.split(","));
        contextSource.setBase(ldapBase);
        contextSource.setUserDn(bindUser);
        contextSource.setPassword(bindPassword);
        return contextSource;
    }

    @Bean
    public LdapTemplate ldapTemplate() {
        return new LdapTemplate(contextSource());
    }

    @Bean
    public LdapClient ldapClient() {
        return new LdapClient();
    }
}
