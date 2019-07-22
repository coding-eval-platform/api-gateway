package ar.edu.itba.cep.api_gateway.security.bearer;

import ar.edu.itba.cep.api_gateway.security.AnonymousAccess;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Optional;

/**
 * A {@link ServerAuthenticationConverter} that takes a bearer token from a {@link ServerWebExchange}, and transforms
 * it into a {@link PreAuthenticatedBearerToken}, wrapped in a {@link Mono},
 * according to the {@link ServerAuthenticationConverter#convert(ServerWebExchange)} method.
 */
@Component
public class BearerTokenAuthenticationConverter implements ServerAuthenticationConverter {

    @Override
    public Mono<Authentication> convert(final ServerWebExchange exchange) {
        return extractJwtToken(exchange)
                .map(PreAuthenticatedBearerToken::new)
                .cast(Authentication.class)
                .defaultIfEmpty(AnonymousAccess.getInstance())
                ;
    }

    /**
     * Extracts a JWT token from the given {@link ServerWebExchange}.
     *
     * @param exchange The {@link ServerWebExchange} from where the token will be extracted.
     * @return A {@link Mono} containing the JWT if it exists in the {@code exchange}, or empty
     * otherwise.
     * @implNote This method searches for the {@link Constants#BEARER_SCHEME} header in the {@code request}
     * in the given {@code exchange}, which should contain the token with the following format:
     * Bearer&lt;space&gt;&lt;token&gt;.
     */
    private static Mono<String> extractJwtToken(final ServerWebExchange exchange) {
        Assert.notNull(exchange, "The exchange must not be null");
        return Mono.justOrEmpty(exchange)
                .map(ServerWebExchange::getRequest)
                .map(ServerHttpRequest::getHeaders)
                .<String>handle(
                        (headers, sink) ->
                                Optional.ofNullable(headers.getFirst(HttpHeaders.AUTHORIZATION)).ifPresent(sink::next)
                )
                .filter(StringUtils::hasText)
                .map(header -> header.split(" "))
                .filter(splitted -> splitted.length == 2)
                .filter(splitted -> Constants.BEARER_SCHEME.equals(splitted[0]))
                .map(splitted -> splitted[1])
                ;
    }
}
