package th.co.ktb.spig.authentication;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.info.BuildProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.scheduling.annotation.EnableScheduling;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;

@SpringBootApplication
@EnableScheduling
@ComponentScan(basePackages = "com.ibm.th.microservice.framework, th.co.ktb.spig.authentication")
public class CentralAuthenticationApp {

    @Autowired
    BuildProperties buildProperties;

    public static void main(String[] args) throws Exception {

        SpringApplication.run(CentralAuthenticationApp.class);
    }

    private ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title("KTB RESTful APIs")
                .contact(new Contact("Krungthai Bank Public Company Limited", "https://www.ktb.co.th", ""))
                // Use build version from Maven POM
                .version(buildProperties.getVersion())
                .build();
    }

}