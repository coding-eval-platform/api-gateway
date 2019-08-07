package ar.edu.itba.cep.api_gateway.security.cors;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;

import java.time.Duration;

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
    public void afterPropertiesSet() throws Exception {
        corsConfiguration.addAllowedOrigin(CorsConfiguration.ALL);
        corsConfiguration.addAllowedMethod(CorsConfiguration.ALL);
        corsConfiguration.addAllowedHeader(CorsConfiguration.ALL);
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.setMaxAge(Duration.ofHours(1L).getSeconds()); // One hour TODO: configurable?
        // 'Access-Control-Expose-Headers' is not set as we want to expose all headers, feature not allowed
        // by the CorsConfiguration class.
    }


    @Override
    public CorsConfiguration getCorsConfiguration(final ServerWebExchange exchange) {
        return corsConfiguration;
    }
}
