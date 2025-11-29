package com.github.jvalkeal.secpat.idserver;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import com.github.jvalkeal.secpat.common.CommonJdbcConfiguration;
import com.github.jvalkeal.secpat.common.CommonPatConfiguration;
import com.github.jvalkeal.secpat.server.pat.PatAuthorizationServerConfigurer;
import com.github.jvalkeal.secpat.server.pat.PatAuthorizationServerSettings;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
@Import({ CommonPatConfiguration.class, CommonJdbcConfiguration.class })
public class IdServerConfiguration {

	@Bean
	@Order(1)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
			throws Exception {
		// Add pat configuration to authz server
		PatAuthorizationServerConfigurer patAuthorizationServer = PatAuthorizationServerConfigurer.dsl();
		http
			.with(patAuthorizationServer, (pat) -> {
				pat.patAuthorizationServerSettings(PatAuthorizationServerSettings.builder().build());
				pat.tokenIntrospectionEndpoint(withDefaults());
		});

		http
			.oauth2AuthorizationServer((authorizationServer) -> {
				// Only extension point to sneak in pat endpoint together with other authz endpoints
				http.securityMatchers(matchers -> {
					matchers.requestMatchers(
						authorizationServer.getEndpointsMatcher(),
						patAuthorizationServer.getEndpointsMatcher()
					);
				});
				authorizationServer
					.oidc(Customizer.withDefaults());
			})
			.authorizeHttpRequests((authorize) ->
				authorize
					.anyRequest().authenticated()
			);

		http
			.exceptionHandling((exceptions) -> exceptions
				.defaultAuthenticationEntryPointFor(
					new LoginUrlAuthenticationEntryPoint("/login"),
					new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
				)
			)
			.oauth2ResourceServer((resourceServer) -> resourceServer.jwt(withDefaults()));
		return http.build();
	}

	@Bean
	@Order(2)
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests((authorize) -> authorize
				.anyRequest().authenticated()
			)
			.formLogin(Customizer.withDefaults());
		return http.build();
	}

	@SuppressWarnings("deprecation")
	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails userDetails1 = User.withDefaultPasswordEncoder()
				.username("user")
				.password("password")
				.roles("USER")
				.build();
		UserDetails userDetails2 = User.withDefaultPasswordEncoder()
				.username("admin")
				.password("password")
				.roles("USER", "ADMIN")
				.build();
		return new InMemoryUserDetailsManager(userDetails1, userDetails2);
	}

}
