//package th.co.ktb.spig.authentication.config;
//
//import org.apache.http.client.HttpClient;
//import org.apache.http.impl.client.HttpClientBuilder;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.http.client.ClientHttpRequestFactory;
//import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
//import org.springframework.http.converter.StringHttpMessageConverter;
//import org.springframework.web.client.RestTemplate;
//
//import java.nio.charset.StandardCharsets;
//
//@Configuration
//public class RestTemplateConfiguration {
//
////    @Autowired
////    private SSLContext sslContext;
//    //https://stackoverflow.com/questions/33497874/resttemplate-with-pem-certificate
//
//    @Bean(name = "httpClient")
//    public HttpClient httpClient() throws Exception {
//        return HttpClientBuilder.create()
//                .build();
//    }
//
//    @Bean
//    public ClientHttpRequestFactory httpClientRequestFactory() throws Exception {
//        return new HttpComponentsClientHttpRequestFactory(httpClient());
//    }
//
//    @Bean
//    public RestTemplate restTemplate() throws Exception {
//        // Fix Http error response for 401 https://stackoverflow.com/questions/54932011/responseentityexceptionhandler-returns-empty-response-body-for-401-exceptions
//        RestTemplate restTemplate = new RestTemplate(httpClientRequestFactory());
//        restTemplate.getMessageConverters().add(0, new StringHttpMessageConverter(StandardCharsets.UTF_8));
//        return restTemplate;
//    }
//
//}
