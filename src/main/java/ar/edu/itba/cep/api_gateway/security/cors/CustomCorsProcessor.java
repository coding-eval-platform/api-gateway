package ar.edu.itba.cep.api_gateway.security.cors;

import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.DefaultCorsProcessor;
import org.springframework.web.server.ServerWebExchange;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

import static org.springframework.http.HttpHeaders.*;

/**
 * A custom {@link org.springframework.web.cors.reactive.CorsProcessor} that extends the {@link DefaultCorsProcessor}
 * in order to set the 'Access-Control-Expose-Headers' with the headers included both in the
 * {@link CorsConfiguration#getExposedHeaders()} {@link List}, and in the 'Access-Control-Request-Headers' included
 * in the incoming request.
 */
@Component
public class CustomCorsProcessor extends DefaultCorsProcessor {


    @Override
    protected boolean handleInternal(
            final ServerWebExchange exchange,
            final CorsConfiguration config,
            final boolean isPreFlightRequest) {

        final var request = exchange.getRequest();
        final var responseHeaders = exchange.getResponse().getHeaders();
        responseHeaders.addAll(VARY, VARY_HEADERS);
        try {
            Optional.ofNullable(request.getHeaders().getOrigin())
                    .map(o -> checkOrigin(config, o))
                    .ifPresentOrElse(
                            responseHeaders::setAccessControlAllowOrigin,
                            CustomCorsProcessor::handleRequestRejected
                    );
            Optional.of(getMethodToUse(request, isPreFlightRequest))
                    .map(m -> checkMethods(config, m))
                    .ifPresentOrElse(
                            allowMethods -> {
                                if (isPreFlightRequest) {
                                    responseHeaders.setAccessControlAllowMethods(allowMethods);
                                }
                            },
                            CustomCorsProcessor::handleRequestRejected
                    );
            Optional.of(getHeadersToUse(request, isPreFlightRequest))
                    .map(h -> checkHeaders(config, h))
                    .ifPresentOrElse(
                            allowHeaders -> {
                                if (isPreFlightRequest && !allowHeaders.isEmpty()) {
                                    responseHeaders.setAccessControlAllowHeaders(allowHeaders);
                                }
                                final List<String> exposedHeaders = new LinkedList<>(allowHeaders);
                                Optional.ofNullable(config.getExposedHeaders()).ifPresent(exposedHeaders::addAll);
                                responseHeaders.setAccessControlExposeHeaders(exposedHeaders);
                            },
                            CustomCorsProcessor::handleRequestRejected
                    );
            Optional.ofNullable(config.getAllowCredentials())
                    .ifPresent(responseHeaders::setAccessControlAllowCredentials);
            Optional.ofNullable(config.getMaxAge())
                    .filter(ignored -> isPreFlightRequest)
                    .ifPresent(responseHeaders::setAccessControlMaxAge);

        } catch (final RequestRejectedException e) {
            rejectRequest(exchange.getResponse());
            return false;
        }
        return true;
    }

    /**
     * Returns the {@link HttpMethod} to be used when setting the 'Access-Control-Allow-Method' header.
     *
     * @param request     The {@link ServerHttpRequest} to be analyzed.
     * @param isPreFlight A flag indicating whether the request is a preflight request.
     * @return The {@link HttpMethod}.
     */
    private static HttpMethod getMethodToUse(final ServerHttpRequest request, final boolean isPreFlight) {
        return isPreFlight ? request.getHeaders().getAccessControlRequestMethod() : request.getMethod();
    }

    /**
     * Returns a {@link List} of {@link String} indicating the headers to be used when setting the
     * 'Access-Control-Allow-Headers' and 'Access-Control-Expose-Headers' headers.
     *
     * @param request     The {@link ServerHttpRequest} to be analyzed.
     * @param isPreFlight A flag indicating whether the request is a preflight request.
     * @return The {@link HttpMethod}.
     */
    private static List<String> getHeadersToUse(final ServerHttpRequest request, final boolean isPreFlight) {
        final var headers = request.getHeaders();
        return isPreFlight ? headers.getAccessControlRequestHeaders() : new ArrayList<>(headers.keySet());
    }

    /**
     * Handles the situation in which the request is rejected due to a failed CORS check.
     */
    private static void handleRequestRejected() {
        throw new RequestRejectedException();
    }

    /**
     * An exception to be thrown when a request is rejected due to a failed CORS check.
     */
    private static final class RequestRejectedException extends RuntimeException {
    }

    /**
     * The {@link List} of headers to be set in the 'Vary' header in a CORS request.
     */
    private static final List<String> VARY_HEADERS = List.of(
            ORIGIN,
            ACCESS_CONTROL_REQUEST_METHOD,
            ACCESS_CONTROL_REQUEST_HEADERS
    );
}
