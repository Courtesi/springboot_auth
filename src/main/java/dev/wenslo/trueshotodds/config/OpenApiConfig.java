package dev.wenslo.trueshotodds.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.Components;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Value("${app.mail.base-url:http://localhost:8080}")
    private String baseUrl;

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .servers(List.of(new Server().url(baseUrl)))
                .info(new Info()
                        .title("TrueShotOdds Authentication API")
                        .description("Spring Boot authentication backend with session management, user registration, and profile management")
                        .version("1.0.0")
                        .contact(new Contact()
                                .name("TrueShotOdds")
                                .email("support@trueshotodds.com")))
                .components(new Components()
                        .addSecuritySchemes("session-auth", new SecurityScheme()
                                .type(SecurityScheme.Type.APIKEY)
                                .in(SecurityScheme.In.COOKIE)
                                .name("JSESSIONID")
                                .description("Session-based authentication using cookies")))
                .addSecurityItem(new SecurityRequirement().addList("session-auth"));
    }
}