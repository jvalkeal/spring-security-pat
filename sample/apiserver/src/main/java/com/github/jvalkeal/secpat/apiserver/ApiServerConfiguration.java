package com.github.jvalkeal.secpat.apiserver;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import com.github.jvalkeal.secpat.pat.config.PatConfigurer;
import com.github.jvalkeal.secpat.pat.introspect.SpringAuthServerPatIntrospector;

@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
@Configuration(proxyBeanMethods = false)
public class ApiServerConfiguration {

	@Profile("authserver")
	@Configuration(proxyBeanMethods = false)
	static class WithAuthServerConfiguration {

		@Bean
		public SecurityFilterChain secFilterChain(HttpSecurity http) throws Exception {
			http.authorizeHttpRequests(authorize -> { authorize
				.requestMatchers("/api/**").authenticated();
			});
			http.with(PatConfigurer.dsl(), pat -> {
				// pat.endpointIntrospection(withDefaults());
				SpringAuthServerPatIntrospector patIntrospector = SpringAuthServerPatIntrospector.builder()
					.introspectionUri("http://idserver:9000/pat/introspect")
					.clientId("oidc-client")
					.clientSecret("secret")
					.build();
				pat.introspector(patIntrospector);
			});
			http.oauth2Login(withDefaults());
			http.oauth2Client(withDefaults());
			http.oauth2ResourceServer((resourceServer) -> resourceServer.jwt(withDefaults()));
			return http.build();
		}

	}

	@Profile("!authserver")
	@Configuration(proxyBeanMethods = false)
	// @Import({ CommonPatConfiguration.class })
	static class WithoutAuthServerConfiguration {

		@Bean
		public SecurityFilterChain secFilterChain(HttpSecurity http) throws Exception {
			http.authorizeHttpRequests(authorize -> { authorize
				.requestMatchers("/api/**").authenticated();
			});
			http.with(PatConfigurer.dsl(), withDefaults());
			http.oauth2Login(withDefaults());
			http.oauth2Client(withDefaults());
			http.oauth2ResourceServer((resourceServer) -> resourceServer.jwt(withDefaults()));
			return http.build();
		}

	}

}
