package org.pitest.mutationtest.engine.gregor.mutators.experimental;

import org.junit.Test;
import org.pitest.verifier.mutants.MutatorVerifierStart;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.Collections;
import java.util.concurrent.Callable;

import static org.pitest.mutationtest.engine.gregor.mutators.experimental.AuthTokenIsAlwaysAuthenticatedMutator.AUTH_TOKEN_IS_ALWAYS_AUTHENTICATED_MUTATOR;

public class AuthTokenIsAlwaysAuthenticatedMutatorTest {

    MutatorVerifierStart verifier = MutatorVerifierStart
            .forMutator(AUTH_TOKEN_IS_ALWAYS_AUTHENTICATED_MUTATOR)
            .notCheckingUnMutatedValues();

    @Test
    public void isAuthenticatedTest() {
        verifier.forCallableClass(IsAuthenticatedTestClass.class)
                .firstMutantShouldReturn(true);
    }

    private static final class IsAuthenticatedTestClass implements Callable<Boolean> {

        @Override
        public Boolean call() {
            Authentication authentication = new TestAuthenticationToken();
            return authentication.isAuthenticated();
        }
    }

    private static final class TestAuthenticationToken extends AbstractAuthenticationToken implements Authentication {

        public TestAuthenticationToken() {
            super(Collections.emptyList());
        }

        @Override
        public boolean isAuthenticated() {
            return false;
        }

        @Override
        public Object getCredentials() {
            return null;
        }

        @Override
        public Object getPrincipal() {
            return null;
        }
    }
}
