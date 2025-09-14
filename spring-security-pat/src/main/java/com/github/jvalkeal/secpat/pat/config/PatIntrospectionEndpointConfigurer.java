package com.github.jvalkeal.secpat.pat.config;

import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class PatIntrospectionEndpointConfigurer extends AbstractPatConfigurer {

	protected PatIntrospectionEndpointConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
		//TODO Auto-generated constructor stub
	}

	@Override
	public void init(HttpSecurity httpSecurity) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Unimplemented method 'init'");
	}

	@Override
	public void configure(HttpSecurity httpSecurity) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Unimplemented method 'configure'");
	}

	@Override
	public RequestMatcher getRequestMatcher() {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Unimplemented method 'getRequestMatcher'");
	}

}
