package com.github.jvalkeal.secpat.apiserver;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

class ApiAccountToken extends AbstractAuthenticationToken {

	private final ApiAccount apiAccount;

	public ApiAccountToken(ApiAccount apiAccount, Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.apiAccount = apiAccount;
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public Object getPrincipal() {
		return this.apiAccount;
	}

}