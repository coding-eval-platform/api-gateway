package ar.edu.itba.cep.api_gateway;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration class for the API gateway routes.
 */
@Configuration
public class RoutesConfig {

    /**
     * Creates a bean of {@link RouteLocator} in order to setup the routes the API gateway will handle.
     *
     * @param builder The {@link RouteLocatorBuilder} used to create the {@link RouteLocator}.
     * @return A bean of a {@link RouteLocator} configured to handle the API gateway's routes.
     */
    @Bean
    public RouteLocator routes(final RouteLocatorBuilder builder) {
        return builder.routes()
                .route(
                        "playground-service",
                        r -> r
                                .path("/execution-requests/**")
                                .uri("lb://playground-service")
                )
                .route(
                        "evaluations-service",
                        r -> r
                                .path("/exams/**")
                                .or()
                                .path("/exercises/**")
                                .or()
                                .path("/test-cases/**")
                                .and()
                                .uri("lb://evaluations-service")
                )
                .route(
                        "users-service",
                        r -> r
                                .path("/users/**")
                                .uri("lb://users-service")
                )
                .build();
    }
}
