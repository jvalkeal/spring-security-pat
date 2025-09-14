package com.github.jvalkeal.secpat.apiserver;

import static org.springframework.security.config.Customizer.withDefaults;

import java.util.Collection;
import java.util.Collections;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import com.github.jvalkeal.secpat.common.CommonPatConfiguration;
import com.github.jvalkeal.secpat.pat.config.PatConfigurer;
import com.github.jvalkeal.secpat.pat.introspect.SpringAuthServerPatIntrospector;

import static org.springframework.security.config.Customizer.withDefaults;

// @EnableWebSecurity
// @EnableMethodSecurity(securedEnabled = true)
// @Configuration(proxyBeanMethods = false)
// @Import({ CommonPatConfiguration.class })
public class ApiServerConfigurationOld {

	// public SecurityFilterChain xxx(HttpSecurity http) throws Exception {
	// 	http.with(PatConfigurer.dsl(), withDefaults());
	// 	return http.build();
	// }

	@Profile("!authserver")
	@Bean
	@Order(1)
	public SecurityFilterChain filterChain1(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(authorize -> { authorize
			.requestMatchers("/api/**").authenticated()
			// .requestMatchers("/read").hasAnyAuthority("data:read")
			// .requestMatchers("/write").hasAnyAuthority("data:write")
			// .anyRequest().authenticated()
			;
		});
		http.with(PatConfigurer.dsl(), pat -> {

		});
		http.oauth2Login(withDefaults());
		http.oauth2Client(withDefaults());
		http.oauth2ResourceServer((resourceServer) -> resourceServer.jwt(withDefaults()));
		return http.build();
	}

	@Profile("authserver")
	@Bean
	@Order(1)
	public SecurityFilterChain filterChain2(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(authorize -> { authorize
			.requestMatchers("/api/**").authenticated()
			// .requestMatchers("/read").hasAnyAuthority("data:read")
			// .requestMatchers("/write").hasAnyAuthority("data:write")
			// .anyRequest().authenticated()
			;
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
		// http.oauth2ResourceServer((resourceServer) -> resourceServer.jwt(jwt -> {
		// 	jwt.jwtAuthenticationConverter(new ApiAccountJwtAuthenticationConverter());
		// }));
		// ApiAccountJwtAuthenticationConverter
		return http.build();
	}

	// @Bean
	// public Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter() {

	// 	JwtGrantedAuthoritiesConverter converter = new JwtGrantedAuthoritiesConverter();
	// 	// if (StringUtils.hasText(mappingProps.getAuthoritiesPrefix())) {
	// 	// 	converter.setAuthorityPrefix(mappingProps.getAuthoritiesPrefix().trim());
	// 	// }
	// 	return converter;
	// }

	// @Bean
	// public JwtAuthenticationConverter customJwtAuthenticationConverter() {
	// 	JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
	// 	converter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter());
	// 	return converter;
	// }

	static class ApiAccountJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

		// ...private fields and construtor omitted
		@Override
		public AbstractAuthenticationToken convert(Jwt source) {

			// Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(source);
			// String principalClaimValue = source.getClaimAsString(this.principalClaimName);
			// Account acc = accountService.findAccountByPrincipal(principalClaimValue);
			// return new AccountToken(source, authorities, principalClaimValue, acc);
			ApiAccount apiAccount = new ApiAccount();
			ApiAccountToken apiAccountToken = new ApiAccountToken(apiAccount, Collections.emptySet());
			return apiAccountToken;
		}
	}
}