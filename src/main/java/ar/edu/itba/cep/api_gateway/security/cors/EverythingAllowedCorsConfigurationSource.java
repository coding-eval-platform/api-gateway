package ar.edu.itba.cep.api_gateway.security.cors;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;

import java.time.Duration;
import java.util.List;

/**
 * A {@link CorsConfigurationSource} that allows all origins, methods, headers, etc.
 */
@Component
public class EverythingAllowedCorsConfigurationSource implements CorsConfigurationSource, InitializingBean {

    /**
     * The {@link CorsConfiguration} supplied by this {@link CorsConfigurationSource}.
     */
    private final CorsConfiguration corsConfiguration;

    /**
     * Constructor.
     */
    public EverythingAllowedCorsConfigurationSource() {
        this.corsConfiguration = new CorsConfiguration();
    }

    @Override
    public void afterPropertiesSet() {
        corsConfiguration.addAllowedOrigin(CorsConfiguration.ALL);
        corsConfiguration.addAllowedMethod(CorsConfiguration.ALL);
        corsConfiguration.addAllowedHeader(CorsConfiguration.ALL);
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.setMaxAge(Duration.ofHours(1L).getSeconds()); // One hour TODO: configurable?
        corsConfiguration.setExposedHeaders(List.of(
                HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS,
                HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS,
                HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN,
                HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS,
                HttpHeaders.ACCESS_CONTROL_MAX_AGE,
                HttpHeaders.ACCEPT_RANGES,
                HttpHeaders.AGE,
                HttpHeaders.ALLOW,
                HttpHeaders.CONNECTION,
                HttpHeaders.CONTENT_DISPOSITION,
                HttpHeaders.CONTENT_ENCODING,
                HttpHeaders.CONTENT_LENGTH,
                HttpHeaders.CONTENT_LOCATION,
                HttpHeaders.CONTENT_RANGE,
                HttpHeaders.DATE,
                HttpHeaders.ETAG,
                HttpHeaders.LINK,
                HttpHeaders.LOCATION,
                HttpHeaders.PROXY_AUTHENTICATE,
                HttpHeaders.RETRY_AFTER,
                HttpHeaders.SERVER,
                HttpHeaders.TRANSFER_ENCODING,
                HttpHeaders.TRANSFER_ENCODING,
                HttpHeaders.UPGRADE,
                HttpHeaders.VARY,
                HttpHeaders.VIA,
                HttpHeaders.WARNING,
                HttpHeaders.WWW_AUTHENTICATE,

                CONTENT_TYPE_OPTIONS,
                FRAME_OPTIONS,
                STRICT_TRANSPORT_SECURITY,
                XSS_PROTECTION

        ));
    }


    @Override
    public CorsConfiguration getCorsConfiguration(final ServerWebExchange exchange) {
        return corsConfiguration;
    }


    // ========================================
    // Spring Security headers
    // ========================================

    private static final String CONTENT_TYPE_OPTIONS = "X-Content-Type-Options";
    private static final String FRAME_OPTIONS = "X-Frame-Options";
    private static final String STRICT_TRANSPORT_SECURITY = "Strict-Transport-Security";
    private static final String XSS_PROTECTION = "X-XSS-Protection";
}
