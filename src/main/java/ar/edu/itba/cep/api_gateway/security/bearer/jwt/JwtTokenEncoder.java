package ar.edu.itba.cep.api_gateway.security.bearer.jwt;

import ar.edu.itba.cep.api_gateway.security.bearer.BearerTokenAuthentication;
import ar.edu.itba.cep.api_gateway.security.bearer.TokenEncoder;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;

import java.security.PrivateKey;
import java.util.stream.Collectors;

/**
 * An implementation of a {@link TokenEncoder} using the JWT specification.
 */
@Component
public class JwtTokenEncoder implements TokenEncoder {

    /**
     * The {@link PrivateKey} used to sign internal tokens.
     */
    private final PrivateKey privateKey;


    /**
     * Constructor.
     *
     * @param privateKey The {@link PrivateKey} used to sign internal tokens.
     */
    @Autowired
    public JwtTokenEncoder(final PrivateKey privateKey) {
        this.privateKey = privateKey;
    }


    @Override
    public Mono<String> encode(final BearerTokenAuthentication bearerTokenAuthentication) {
        Assert.notNull(bearerTokenAuthentication, "The bearer token authentication must not be null");
        return Mono.defer(() ->
                Mono.just(bearerTokenAuthentication)
                        .map(auth -> {
                                    final var id = auth.getTokenId().toString();
                                    final var username = auth.getUsername();
                                    final var roles = auth.getAuthorities()
                                            .stream()
                                            .map(GrantedAuthority::getAuthority)
                                            .collect(Collectors.toList());

                                    return Jwts.builder()
                                            .setId(id)
                                            .setSubject(username)
                                            .claim(Constants.ROLES_CLAIM, roles)
                                            .signWith(privateKey, Constants.SIGNATURE_ALGORITHM)
                                            .compact()
                                            ;
                                }
                        )
        );
    }

}
