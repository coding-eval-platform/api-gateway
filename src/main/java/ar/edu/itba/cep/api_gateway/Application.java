package ar.edu.itba.cep.api_gateway;

import org.springframework.boot.Banner;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

/**
 * Bootstrap class.
 */
@SpringBootApplication
public class Application {
    /**
     * Entry point.
     *
     * @param args Program arguments.
     */
    public static void main(String[] args) {
        new SpringApplicationBuilder(Application.class)
                .bannerMode(Banner.Mode.OFF)
                .build().run(args);
    }
}
