package th.co.ktb.spig.authentication.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.util.Optional;

import static springfox.documentation.builders.PathSelectors.regex;

/**
 * Configuration for swagger dockets
 *
 * Creates two groups internal and external
 *  internal contains the sourceSystem
 *  external contains apiKey and apiSecret
 *
 * The reason behind this, is that there is a gateway between
 * clients and the microservices, that transforms apiKey and apiSecret
 * into sourceSystem. Externally the API documentation must be
 * presented with apiKey and apiSecret
 *
 */
@Configuration
@EnableSwagger2
public class SwaggerConfiguration {


    //--------- FOR SPRINGFOX SWAGGER UI (only single implementation per mircoservice application) ---------------------
    @Bean
    protected ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title("KTB Central Authentication RESTful API")
                .contact(new Contact("IBM Thailand Co.,Ltd.", "", "aruplaha@in.ibm.com"))
                .description("KTB entral Authentication RESTful API")
                .termsOfServiceUrl("http://www-03.ibm.com/software/sla/sladb.nsf/sla/bm?Open")
                .license("Apache License Version 2.0")
                .licenseUrl("https://github.com/IBM-Bluemix/news-aggregator/blob/master/LICENSE")
                .version("1.0")
                .build();
    }

    @Bean
    public Docket internalApi() {

        Docket thisDocket;
        thisDocket = new Docket(DocumentationType.SWAGGER_2)
                // Optional
                .groupName("Central Authentication APIs")
                .apiInfo(apiInfo())
                .select()
                .apis(RequestHandlerSelectors.any())
                .paths(regex("/v[0-9].*"))
                .build()
                .genericModelSubstitutes(Optional.class) // add this
                .ignoredParameterTypes();
        return thisDocket;
    }
}
