package org.pitest.mutationtest.engine.gregor.mutators.experimental;

import org.junit.Test;
import org.pitest.verifier.mutants.MutatorVerifierStart;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collections;
import java.util.concurrent.Callable;

import static org.pitest.mutationtest.engine.gregor.mutators.experimental.spring.AlwaysEnabledUserDetailsMutator.ALWAYS_ENABLED_USER_DETAILS_MUTATOR;

public class AlwaysEnabledUserDetailsMutatorTest {

    MutatorVerifierStart verifier = MutatorVerifierStart
            .forMutator(ALWAYS_ENABLED_USER_DETAILS_MUTATOR)
            .notCheckingUnMutatedValues();

    @Test
    public void isEnabledTest() {
        verifier.forCallableClass(IsEnabledTestClass.class).firstMutantShouldReturn(true);
    }

    @Test
    public void isAccountNonExpiredTest() {
        verifier.forCallableClass(IsAccountNonExpiredTestClass.class).firstMutantShouldReturn(true);
    }

    @Test
    public void isAccountNonLockedTest() {
        verifier.forCallableClass(IsAccountNonLockedTestClass.class).firstMutantShouldReturn(true);
    }

    @Test
    public void isCredentialsNonExpiredTest() {
        verifier.forCallableClass(IsCredentialsNonExpiredTestClass.class).firstMutantShouldReturn(true);
    }

    private static class IsEnabledTestClass implements Callable<Boolean> {

        @Override
        public Boolean call() throws Exception {
            UserDetails userDetails = someUserDetails();
            return userDetails.isEnabled();
        }
    }

    private static class IsCredentialsNonExpiredTestClass implements Callable<Boolean> {

        @Override
        public Boolean call() throws Exception {
            UserDetails userDetails = someUserDetails();
            return userDetails.isCredentialsNonExpired();
        }
    }

    private static class IsAccountNonLockedTestClass implements Callable<Boolean> {

        @Override
        public Boolean call() throws Exception {
            UserDetails userDetails = someUserDetails();
            return userDetails.isAccountNonLocked();
        }
    }

    private static class IsAccountNonExpiredTestClass implements Callable<Boolean> {

        @Override
        public Boolean call() throws Exception {
            UserDetails userDetails = someUserDetails();
            return userDetails.isAccountNonExpired();
        }
    }

    public static UserDetails someUserDetails() {
        return new User("jeff",
                "jeff",
                false,
                false,
                false,
                false,
                Collections.emptyList());
    }
}
