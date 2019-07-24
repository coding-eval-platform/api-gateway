package ar.edu.itba.cep.api_gateway.security.bearer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Component;
import org.springframework.util.ClassUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * A {@link GlobalFilter} that changes the external bearer token to an internal bearer token.
 */
@Component
public class BearerTokenTranslator implements GlobalFilter {

    /**
     * The {@link TokenEncoder} used to create a raw token from a {@link BearerTokenAuthentication}.
     */
    private final TokenEncoder tokenEncoder;


    /**
     * Constructor.
     *
     * @param tokenEncoder The {@link TokenEncoder} used to create a raw token from a {@link BearerTokenAuthentication}.
     */
    @Autowired
    public BearerTokenTranslator(final TokenEncoder tokenEncoder) {
        this.tokenEncoder = tokenEncoder;
    }


    @Override
    public Mono<Void> filter(final ServerWebExchange exchange, final GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(a -> ClassUtils.isAssignable(BearerTokenAuthentication.class, a.getClass()))
                .cast(BearerTokenAuthentication.class)
                .flatMap(tokenEncoder::encode)
                .map(rawToken -> setAuthorization(exchange.getRequest(), rawToken))
                .map(request -> setRequest(exchange, request))
                .defaultIfEmpty(exchange)
                .flatMap(chain::filter)
                ;
    }


    /**
     * Sets or replaces the {@link HttpHeaders#AUTHORIZATION} header in the given {@code request}
     * with the given {@code rawToken}, returning a mutated {@link ServerHttpRequest}.
     *
     * @param request  The {@link ServerHttpRequest} to be modified.
     * @param rawToken The token to be included in the {@link HttpHeaders#AUTHORIZATION} header,
     *                 using the {@link Constants#BEARER_SCHEME} scheme.
     * @return A mutated {@link ServerHttpRequest}, based on the given {@code request},
     * but with the {@link HttpHeaders#AUTHORIZATION} header containing the given {@code rawToken},
     * using the {@link Constants#BEARER_SCHEME} scheme.
     */
    private static ServerHttpRequest setAuthorization(final ServerHttpRequest request, final String rawToken) {
        return request.mutate()
                .headers(headers -> headers.remove(HttpHeaders.AUTHORIZATION))
                .header(HttpHeaders.AUTHORIZATION, Constants.BEARER_SCHEME + " " + rawToken)
                .build();
    }

    /**
     * Sets or replace the {@link ServerHttpRequest} in the given {@code exchange} with the given {@code request},
     * returning a mutated {@link ServerWebExchange}.
     *
     * @param exchange The {@link ServerWebExchange} to be modified.
     * @param request  The new {@link ServerHttpRequest}.
     * @return A mutated {@link ServerWebExchange}, based on the given {@code exchange},
     * but with the given {@code request}.
     */
    private static ServerWebExchange setRequest(final ServerWebExchange exchange, final ServerHttpRequest request) {
        return exchange.mutate()
                .request(request)
                .build();
    }
}
