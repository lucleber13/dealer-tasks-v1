package com.cbcode.dealertasksV1.Users.security.Impl;

import com.cbcode.dealertasksV1.Users.security.SecurityUserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.web.config.EnableSpringDataWebSupport;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@EnableSpringDataWebSupport(pageSerializationMode = EnableSpringDataWebSupport.PageSerializationMode.VIA_DTO)
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    private final JwtAuthFilter jwtAuthFilter;
    private final SecurityUserService securityUserService;

    public SecurityConfig(JwtAuthFilter jwtAuthFilter, SecurityUserService securityUserService) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.securityUserService = securityUserService;
    }

    /**
     * Configures the security filter chain.
     * Disables CSRF and CORS, or configure them with private methods.
     * Configure the authorization rules for the endpoints.
     * Configure the session management policy.
     * Adds the JWT authentication filter before the UsernamePasswordAuthenticationFilter.
     * @param http the HttpSecurity object
     * @return the SecurityFilterChain object
     * @throws Exception if an error occurs
     * @see SecurityFilterChain for more details.
     * @see HttpSecurity for more details.
     * @see JwtAuthFilter for more details.
     * @see UsernamePasswordAuthenticationFilter for more details.
     * @see SessionCreationPolicy for more details.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        logger.info("Creating security filter chain");
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers("/auth/**").permitAll()
                                .requestMatchers("/cars/users/**").hasAnyRole("ADMIN", "SALES", "WORKSHOP", "VALETER")
                                .requestMatchers("/cars/**").hasAnyRole("ADMIN", "SALES")
                                .requestMatchers("/admin/**").hasRole("ADMIN")
                                .requestMatchers("/users/**").hasAnyRole("SALES", "WORKSHOP", "VALETER")
                                .requestMatchers("/workshop/**").hasAnyRole("ADMIN", "WORKSHOP")
                                .requestMatchers("/valet/**").hasAnyRole("ADMIN", "VALETER")
                                .requestMatchers("/tasks/**").hasAnyRole("ADMIN", "SALES")
                                // TODO: Remove in production
                                .requestMatchers("/swagger-ui/**", "/v3/api-docs/**", "/swagger-ui.html/**").permitAll()
                                .anyRequest().authenticated())
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    /**
     * Configures the CORS policy.
     * Allows specific origins, methods, and headers.
     * Apply the configuration to all endpoints.
     * @return the CorsConfigurationSource object
     * @see CorsConfigurationSource for more details.
     * @see CorsConfiguration for more details.
     * @see UrlBasedCorsConfigurationSource for more details.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("http://localhost:3000")); // Update for production
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    /**
     * Configures the authentication provider.
     * Uses the custom UserDetailsService and PasswordEncoder.
     * @return the AuthenticationProvider object
     * @see DaoAuthenticationProvider for more details.
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(securityUserService.getUserDetailsService());
        provider.setPasswordEncoder(passwordEncoder());
        logger.info("Configured DaoAuthenticationProvider with custom UserDetailsService and PasswordEncoder");
        return provider;
    }

    /**
     * Configures the PasswordEncoder.
     * Uses the BCryptPasswordEncoder.
     * @return the PasswordEncoder object
     * @see BCryptPasswordEncoder for more details.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Configures the AuthenticationManager.
     * Uses the AuthenticationConfiguration to get the AuthenticationManager.
     * @param authenticationConfiguration the AuthenticationConfiguration object
     * @return the AuthenticationManager object
     * @throws Exception if an error occurs
     * @see AuthenticationManager for more details.
     * @see AuthenticationConfiguration for more details.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
