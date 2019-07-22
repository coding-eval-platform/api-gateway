package ar.edu.itba.cep.api_gateway.security;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

/**
 * An extension of an {@link AnonymousAuthenticationToken}.
 */
public class AnonymousAccess extends AnonymousAuthenticationToken {

    /**
     * Anonymous.
     */
    private static final String ANONYMOUS = "ANONYMOUS";

    /**
     * The unique instance.
     */
    private static final AnonymousAccess SINGLETON = new AnonymousAccess();

    /**
     * Private constructor.
     * Use {@link #getInstance()} instead.
     */
    private AnonymousAccess() {
        super(ANONYMOUS, ANONYMOUS, List.of(new SimpleGrantedAuthority(ANONYMOUS)));
    }

    /**
     * Access the unique instance of an {@link AnonymousAccess}.
     *
     * @return The unique instance.
     */
    public static AnonymousAccess getInstance() {
        return SINGLETON;
    }
}
