package com.cbcode.dealertasksV1;

import io.github.cdimascio.dotenv.Dotenv;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class DealerTasksV1Application {

    private static final Logger logger = LoggerFactory.getLogger(DealerTasksV1Application.class);

    public static void main(String[] args) {
        SpringApplication application = new SpringApplication(DealerTasksV1Application.class);

        application.addInitializers(
                context -> {
                    ConfigurableEnvironment env = context.getEnvironment();
                    Dotenv dotenv = Dotenv.configure()
                            .directory("./")
                            .filename(".env")
                            .load();

                    Map<String, Object> envMap = new HashMap<>();
                    dotenv.entries().forEach(entry ->
                            envMap.put(entry.getKey().trim(), entry.getValue().trim()));

                    env.getPropertySources().addFirst(new
                            MapPropertySource("dotenv", envMap));
                    logger.info("Dotenv variables loaded successfully");
                });
        application.run(args);
    }

}
