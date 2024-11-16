package com.gifty.authservice.config;

import com.gifty.authservice.filter.JwtAuthenticationFilter;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // CSRF korumasını devre dışı bırakıyoruz
                .cors(cors -> cors.configurationSource(corsConfigurationSource())) // Merkezi CORS yapılandırması
                .authorizeHttpRequests(auth -> auth
                        // Herkese açık endpoint'ler
                        .requestMatchers(
                                "/auth/register", "/auth/login", "/h2-console/**",
                                "/token/refresh", "/token/validate", "/actuator/**"
                        ).permitAll()
                        .requestMatchers("/auth/logout", "/auth/logout-from-all-devices").authenticated() // Logout için doğrulama gereksinimi
                        // Diğer tüm endpoint'ler kimlik doğrulama gerektirir
                        .anyRequest().authenticated()
                )
                // JWT doğrulama filtresi ekleyin
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                // Oturum yönetimini stateless olarak ayarla
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // HSTS yapılandırması (HTTPS kullanıyorsanız önerilir)
                .headers(headers -> headers.httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000)))
                // Exception Handling yapılandırması
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            response.getWriter().write("Unauthorized access.");
                        })
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                            response.getWriter().write("Access denied.");
                        })
                )
                // OAuth2 Login yapılandırması
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/auth/oauth") // OAuth giriş işlemi için özel bir giriş sayfası
                        .defaultSuccessUrl("/auth/success", true) // Başarılı giriş sonrası yönlendirme
                        .failureUrl("/auth/failure") // Başarısız giriş sonrası yönlendirme
                );
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000", "http://127.0.0.1:3000")); // Frontend domain'lerini ekle
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS")); // İzin verilen HTTP metodları
        configuration.setAllowedHeaders(Arrays.asList("*")); // Tüm header'lara izin ver
        configuration.setAllowCredentials(true); // Çerez kullanımına izin ver
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
