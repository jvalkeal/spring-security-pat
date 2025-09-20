package com.github.jvalkeal.secpat.apiserver;

import java.security.Principal;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/whoami")
public class ApiServerWhoamiController {

	private final static Logger log = LoggerFactory.getLogger(ApiServerWhoamiController.class);

	@GetMapping("/authenticationprincipal")
	String whoami1(@AuthenticationPrincipal Object user) {
		String token = "";
		if (user instanceof DefaultOidcUser duser) {
			token = duser.getIdToken().getTokenValue();
		}
		log.debug("User Class {}", user != null ? user.getClass() : null);
		log.debug("User {}", user);
		return String.format("%s - %s - %s", user != null ? user.getClass() : null, user, token);
	}

	@GetMapping("/defaultoidcuser")
	String whoami4(@AuthenticationPrincipal DefaultOidcUser user) {
		log.debug("User Class {}", user != null ? user.getClass() : null);
		log.debug("User {}", user);
		return String.format("%s", user != null ? user.getName() : null);
	}

	@GetMapping("/principal")
	String whoami2(Principal user) {
		String template = """
				Principal class: %s
				User: %s
				Scopes: %s
				""";
		String clazz = (user != null ? user.getClass().toString() : null);
		String name = user != null ? user.getName() : null;
		String scopes = null;
		if (user instanceof Authentication authentication) {
			scopes = authentication.getAuthorities().stream().map(ga -> ga.getAuthority()).collect(Collectors.joining(","));
		}
		log.debug("User Class {}", user != null ? user.getClass() : null);
		log.debug("User {}", user);
		return String.format(template, clazz, name, scopes);
	}

	@GetMapping("/authentication")
	String whoami3(Authentication user) {
		log.debug("User Class {}", user != null ? user.getClass() : null);
		log.debug("User {}", user);
		return String.format("%s - %s", user != null ? user.getClass() : null, user);
	}

}
