package com.github.jvalkeal.secpat.pat.config;

import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.github.jvalkeal.secpat.pat.introspect.PatIntrospector;
import com.github.jvalkeal.secpat.pat.introspect.SpringAuthServerPatIntrospector;

public class PatIntrospectionEndpointConfigurer extends AbstractPatConfigurer {

	private String introspectionUri;

	private String clientId;

	private String clientSecret;

	private PatIntrospector patIntrospector;

	PatIntrospector getPatIntrospector() {
		return patIntrospector;
	}

	protected PatIntrospectionEndpointConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	@Override
	public void init(HttpSecurity httpSecurity) {
	}

	@Override
	public void configure(HttpSecurity httpSecurity) {
		SpringAuthServerPatIntrospector springAuthServerPatIntrospector = SpringAuthServerPatIntrospector.builder()
			.introspectionUri(introspectionUri)
			.clientId(clientId)
			.clientSecret(clientSecret)
			.build();
		this.patIntrospector = springAuthServerPatIntrospector;
	}

	@Override
	public RequestMatcher getRequestMatcher() {
		throw new UnsupportedOperationException("Unimplemented method 'getRequestMatcher'");
	}

	public PatIntrospectionEndpointConfigurer introspectionUri(String introspectionUri) {
		this.introspectionUri = introspectionUri;
		return this;
	}

	public PatIntrospectionEndpointConfigurer clientId(String clientId) {
		this.clientId = clientId;
		return this;
	}

	public PatIntrospectionEndpointConfigurer clientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
		return this;
	}

}
