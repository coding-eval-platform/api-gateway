package ar.edu.itba.cep.api_gateway.security;

import ar.edu.itba.cep.api_gateway.security.bearer.BearerTokenAuthenticationWebFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

/**
 * Configuration class for security aspects.
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    /**
     * Creates a bean of a {@link SecurityWebFilterChain}.
     *
     * @param http                               The {@link ServerHttpSecurity}
     *                                           used to build the {@link SecurityWebFilterChain}.
     * @param bearerTokenAuthenticationWebFilter A {@link BearerTokenAuthenticationWebFilter} used to authenticate
     *                                           requests using the Bearer scheme.
     * @return The created {@link SecurityWebFilterChain} bean.
     */
    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(
            final ServerHttpSecurity http,
            final BearerTokenAuthenticationWebFilter bearerTokenAuthenticationWebFilter) {

        return http
                .csrf()
                    .disable()
                .cors()
                    .disable()
                .formLogin()
                    .disable()
                .httpBasic()
                    .disable()
                .logout()
                    .disable()

                .addFilterAt(bearerTokenAuthenticationWebFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .exceptionHandling()
                    .authenticationEntryPoint((exchange, ignored) -> completeWithStatusCode(exchange, UNAUTHORIZED))
                    .accessDeniedHandler((exchange, ignored) -> completeWithStatusCode(exchange, FORBIDDEN))
                .and()

                .build()
                ;
    }

    /**
     * Takes the {@link ServerHttpResponse} from the given {@code exchange}, sets the given {@link HttpStatus}, and
     * completes the said {@link ServerHttpResponse}.
     *
     * @param exchange The {@link ServerWebExchange} from where the {@link ServerHttpResponse} is taken.
     * @param status   The {@link HttpStatus} to be set.
     * @return The {@link Mono} of {@link Void} returned when completing the {@link ServerHttpResponse}.
     */
    private static Mono<Void> completeWithStatusCode(final ServerWebExchange exchange, final HttpStatus status) {
        return Mono.defer(
                () -> {
                    final var response = exchange.getResponse();
                    response.setStatusCode(status);
                    return response.setComplete();
                }
        );
    }

    /**
     * Creates a bean of a {@link KeyFactory}.
     *
     * @return A {@link KeyFactory} bean.
     * @throws NoSuchAlgorithmException Never.
     */
    @Bean
    public KeyFactory rsaKeyFactory() throws NoSuchAlgorithmException {
        return KeyFactory.getInstance("RSA");
    }
}
