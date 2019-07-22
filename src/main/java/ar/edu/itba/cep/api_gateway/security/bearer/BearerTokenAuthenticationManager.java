package ar.edu.itba.cep.api_gateway.security.bearer;

import ar.edu.itba.cep.api_gateway.security.AnonymousAccess;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.ClassUtils;
import reactor.core.publisher.Mono;


/**
 * A {@link ReactiveAuthenticationManager} that tries to authenticate a {@link PreAuthenticatedBearerToken} using
 * a {@link TokenDecoder}, which is called with the {@link PreAuthenticatedBearerToken#getRawToken()} value.
 */
@Component
public class BearerTokenAuthenticationManager implements ReactiveAuthenticationManager {

    /**
     * The {@link TokenDecoder} used to create a {@link BearerTokenAuthentication} from a raw token.
     */
    private final TokenDecoder tokenDecoder;


    /**
     * Constructor.
     *
     * @param tokenDecoder The {@link TokenDecoder} used to create a {@link BearerTokenAuthentication} from a raw token.
     */
    @Autowired
    public BearerTokenAuthenticationManager(final TokenDecoder tokenDecoder) {
        this.tokenDecoder = tokenDecoder;
    }


    @Override
    public Mono<Authentication> authenticate(final Authentication authentication) {

        if (ClassUtils.isAssignable(PreAuthenticatedBearerToken.class, authentication.getClass())) {
            final var preAuthenticatedAuthenticationToken = (PreAuthenticatedBearerToken) authentication;
            final var rawToken = preAuthenticatedAuthenticationToken.getRawToken();
            return tokenDecoder.decode(rawToken)
                    // TODO: check blacklisted
                    .switchIfEmpty(
                            Mono.defer(
                                    () -> Mono.error(
                                            new BearerTokenAuthenticationException("Token could not be decoded")
                                    )
                            )
                    )
                    .cast(Authentication.class)
                    ;
        }

        return Mono.justOrEmpty(authentication).defaultIfEmpty(AnonymousAccess.getInstance());
    }
}
