package com.github.jvalkeal.secpat.pat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;

import com.github.jvalkeal.secpat.pat.introspect.PatIntrospector;

public class PatAuthenticationProviderTests {

	@Test
	public void authenticateWhenActiveTokenThenOk() throws Exception {
		PatAuthenticatedPrincipal principal = PatAuthenticatedPrincipal.of("user", null);
		PatIntrospector introspector = mock(PatIntrospector.class);
		given(introspector.introspect(any())).willReturn(principal);

		PatAuthenticationProvider provider = new PatAuthenticationProvider(introspector);
		PatTokenAuthenticationToken authenticationToken = PatTokenAuthenticationToken.authenticated("user", null, null);
		Authentication result = provider.authenticate(authenticationToken);
		assertThat(result.getPrincipal()).isInstanceOf(PatAuthenticatedPrincipal.class);

		// Map<String, Object> attributes = ((PatAuthenticatedPrincipal) result.getPrincipal()).getAttributes();

                // OAuth2AuthenticatedPrincipal principal = TestOAuth2AuthenticatedPrincipals
                //         .active((attributes) -> attributes.put("extension_field", "twenty-seven"));
                // OpaqueTokenIntrospector introspector = mock(OpaqueTokenIntrospector.class);
                // given(introspector.introspect(any())).willReturn(principal);
                // OpaqueTokenAuthenticationProvider provider = new OpaqueTokenAuthenticationProvider(introspector);
                // Authentication result = provider.authenticate(new BearerTokenAuthenticationToken("token"));
                // assertThat(result.getPrincipal()).isInstanceOf(OAuth2IntrospectionAuthenticatedPrincipal.class);
                // Map<String, Object> attributes = ((OAuth2AuthenticatedPrincipal) result.getPrincipal()).getAttributes();
                // // @formatter:off
                // assertThat(attributes)
                //                 .isNotNull()
                //                 .containsEntry(OAuth2TokenIntrospectionClaimNames.ACTIVE, true)
                //                 .containsEntry(OAuth2TokenIntrospectionClaimNames.AUD,
                //                                 Arrays.asList("https://protected.example.net/resource"))
                //                 .containsEntry(OAuth2TokenIntrospectionClaimNames.CLIENT_ID, "l238j323ds-23ij4")
                //                 .containsEntry(OAuth2TokenIntrospectionClaimNames.EXP, Instant.ofEpochSecond(1419356238))
                //                 .containsEntry(OAuth2TokenIntrospectionClaimNames.ISS, new URL("https://server.example.com/"))
                //                 .containsEntry(OAuth2TokenIntrospectionClaimNames.NBF, Instant.ofEpochSecond(29348723984L))
                //                 .containsEntry(OAuth2TokenIntrospectionClaimNames.SCOPE, Arrays.asList("read", "write", "dolphin"))
                //                 .containsEntry(OAuth2TokenIntrospectionClaimNames.SUB, "Z5O3upPC88QrAjx00dis")
                //                 .containsEntry(OAuth2TokenIntrospectionClaimNames.USERNAME, "jdoe")
                //                 .containsEntry("extension_field", "twenty-seven");
                // assertThat(result.getAuthorities())
                //                 .extracting("authority")
                //                 .containsExactly("SCOPE_read", "SCOPE_write",
                //                 "SCOPE_dolphin");
                // // @formatter:on

	}
}
