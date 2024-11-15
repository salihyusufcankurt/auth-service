package com.gifty.authservice.config;

import com.gifty.authservice.filter.JwtAuthenticationFilter;
import com.gifty.authservice.service.JwtUtil;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
                .authorizeHttpRequests(auth -> auth
                        // Herkese açık endpoint'ler
                        .requestMatchers("/", "/auth/register", "/auth/login", "/h2-console/**", "/auth/refresh-token").permitAll()
                        .requestMatchers("/auth/logout","/auth/logout-from-all-devices").authenticated() // Logout için doğrulama gereksinimi

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
                        .loginPage("/auth/login") // OAuth giriş işlemi için özel bir giriş sayfası
                        .defaultSuccessUrl("/auth/success", true) // Başarılı giriş sonrası yönlendirme
                        .failureUrl("/auth/failure") // Başarısız giriş sonrası yönlendirme
                );
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

