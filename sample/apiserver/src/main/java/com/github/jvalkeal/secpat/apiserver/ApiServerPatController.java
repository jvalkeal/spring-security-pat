/*
 * Copyright 2025-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.jvalkeal.secpat.apiserver;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Profile;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.github.jvalkeal.secpat.pat.authorization.PatAuthorization;
import com.github.jvalkeal.secpat.pat.authorization.PatAuthorizationRepository;
import com.github.jvalkeal.secpat.pat.keygen.PatService;
import com.github.jvalkeal.secpat.pat.keygen.UUIDPatService;

@Controller
@RequestMapping(path = "/user/pats")
@Profile("postgres")
public class ApiServerPatController {

	private final PatAuthorizationRepository authorizationService;
	private final PatService patService = new UUIDPatService();

	public ApiServerPatController(PatAuthorizationRepository authorizationService) {
		this.authorizationService = authorizationService;
	}

	@GetMapping
	public String listPatsGet(Model model, @AuthenticationPrincipal DefaultOidcUser user) {
		List<ExistingToken> userTokens = getUserTokens(user.getName());
		Tokens tokens = new Tokens(userTokens, null, null);
		model.addAttribute("tokens", tokens);
		return "list-pats";
	}

	private List<ExistingToken> getUserTokens(String principal) {
		return authorizationService.findByPrincipal(principal).stream()
			.map(pa -> {
				return new ExistingToken(pa.getId(), pa.getName(), pa.getDescription(), pa.getExpiresAt());
			})
			.collect(Collectors.toList());
	}

	private boolean hasDuplicateName(String name, List<ExistingToken> userTokens) {
		for (ExistingToken existingToken : userTokens) {
			if (ObjectUtils.nullSafeEquals(name, existingToken.name())) {
				return true;
			}
		}
		return false;
	}

	@PostMapping
	public String listPatsPost(Model model, @AuthenticationPrincipal DefaultOidcUser user, FormData item) {
		String error = null;
		GeneratedToken generated = null;
		if (item.getName() != null) {
			List<ExistingToken> userTokens = getUserTokens(user.getName());
			if (!StringUtils.hasText(item.getName())) {
				error = "Name must be given.";
			}
			else if (hasDuplicateName(item.getName(), userTokens)) {
				error = String.format("Name '%s' is already taken.", item.getName());
			}
			else {
				Instant now = Instant.now();
				Instant month = now.plus(30, ChronoUnit.DAYS);
				String tokenValue = patService.generator().apply(null);
				String id = UUID.randomUUID().toString();
				generated = new GeneratedToken(id, item.getName(), item.getDescription(), month, tokenValue);
				Set<String> scopes = new HashSet<>();
				if (item.isScopeRead()) {
					scopes.add("read");
				}
				if (item.isScopeWrite()) {
					scopes.add("write");
				}
				PatAuthorization patAuthorization = PatAuthorization.builder()
					.id(id)
					.name(item.getName())
					.description(item.getDescription())
					.principal(user.getName())
					.token(tokenValue)
					.scopes(scopes)
					.issuedAt(now)
					.expiresAt(month)
					.notBefore(now)
					.build();
				authorizationService.save(patAuthorization);
			}
			Tokens tokens = new Tokens(userTokens, generated, error);
			model.addAttribute("tokens", tokens);
		}
		else if (item.getId() != null) {
			PatAuthorization byId = authorizationService.findById(item.getId());
			authorizationService.remove(byId);
			List<ExistingToken> userTokens = getUserTokens(user.getName());
			Tokens tokens = new Tokens(userTokens, null, error);
			model.addAttribute("tokens", tokens);
		}
		return "list-pats";
	}

	@GetMapping("/generate")
	public String showGenerateForm(FormData item) {
		return "generate-pat";
	}

	public record Tokens(List<ExistingToken> tokens, GeneratedToken generated, String error) {
	};

	public record GeneratedToken(String id, String name, String description, Instant expiresAt, String content){};

	public record ExistingToken(String id, String name, String description, Instant expiresAt) {
	};

	@ModelAttribute("item")
	public FormData formData() {
		return new FormData();
	}
	public static class FormData {

		private String name;
		private String description;
		private String id;
		private boolean scopeRead;
		private boolean scopeWrite;

		public String getId() {
			return id;
		}

		public void setId(String id) {
			this.id = id;
		}

		public String getName() {
			return name;
		}

		public void setName(String name) {
			this.name = name;
		}

		public String getDescription() {
			return description;
		}

		public void setDescription(String description) {
			this.description = description;
		}

		public boolean isScopeRead() {
			return scopeRead;
		}

		public void setScopeRead(boolean scopeRead) {
			this.scopeRead = scopeRead;
		}

		public boolean isScopeWrite() {
			return scopeWrite;
		}

		public void setScopeWrite(boolean scopeWrite) {
			this.scopeWrite = scopeWrite;
		}

	}

}
