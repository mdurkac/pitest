package org.pitest.mutationtest.engine.gregor.mutators.experimental;

import org.junit.Test;
import org.pitest.verifier.mutants.MutatorVerifierStart;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.util.function.BiFunction;
import java.util.function.Function;

import static org.pitest.mutationtest.engine.gregor.mutators.experimental.spring.NoOpPasswordEncoderMutator.NOOP_PASSWORD_ENCODER;

public class NoOpPasswordEncoderMutatorTest {

    MutatorVerifierStart verifier = MutatorVerifierStart
            .forMutator(NOOP_PASSWORD_ENCODER)
            .notCheckingUnMutatedValues();

    @Test
    public void bcryptInterfaceEncodeTest() {
        verifier.forFunctionClass(BCryptInterfaceEncodeTestClass.class)
                // Expect mutator to use NoOpPasswordEncoder, password is not encoded
                .firstMutantShouldReturn("password", "password");
    }

    private static class BCryptInterfaceEncodeTestClass implements Function<String, String> {

        @Override
        public String apply(String rawPassword) {
            PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
            // This will be mutated
            return passwordEncoder.encode(rawPassword);
        }
    }

    // More unit tests.

    @Test
    public void bcryptInterfaceMatchesTest() {
        verifier.forBiFunctionClass(BCryptInterfaceMatchesTestClass.class)
                .firstMutantShouldReturn("password", "password", true);
        verifier.forBiFunctionClass(BCryptInterfaceMatchesTestClass.class)
                .firstMutantShouldReturn("password", "password2", false);
    }

    private static class BCryptInterfaceMatchesTestClass implements BiFunction<String, String, Boolean> {

        @Override
        public Boolean apply(String rawPassword, String encodedPassword) {
            PasswordEncoder encoder = new BCryptPasswordEncoder();
            return encoder.matches(rawPassword, encodedPassword);
        }
    }

    @Test
    public void bcryptEncodeTest() {
        verifier.forFunctionClass(BCryptEncodeTestClass.class)
                .firstMutantShouldReturn("password", "password");
    }

    @Test
    public void bcryptMatchesTest() {
        verifier.forBiFunctionClass(BCryptMatchesTestClass.class)
                .firstMutantShouldReturn("password", "password", true);
        verifier.forBiFunctionClass(BCryptMatchesTestClass.class)
                .firstMutantShouldReturn("password", "password2", false);
    }

    @Test
    public void scryptEncodeTest() {
        verifier.forFunctionClass(SCryptEncodeTestClass.class)
                .firstMutantShouldReturn("password", "password");
    }

    @Test
    public void scryptMatchesTest() {
        verifier.forBiFunctionClass(SCryptMatchesTestClass.class)
                .firstMutantShouldReturn("password", "password", true);
        verifier.forBiFunctionClass(SCryptMatchesTestClass.class)
                .firstMutantShouldReturn("password", "password2", false);
    }

    @Test
    public void scryptInterfaceEncodeTest() {
        verifier.forFunctionClass(SCryptInterfaceEncodeTestClass.class)
                .firstMutantShouldReturn("password", "password");
    }

    @Test
    public void scryptInterfaceMatchesTest() {
        verifier.forBiFunctionClass(SCryptInterfaceMatchesTestClass.class)
                .firstMutantShouldReturn("password", "password", true);
        verifier.forBiFunctionClass(SCryptInterfaceMatchesTestClass.class)
                .firstMutantShouldReturn("password", "password2", false);
    }
    private static class BCryptEncodeTestClass implements Function<String, String> {

        @Override
        public String apply(String s) {
            BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
            return encoder.encode(s);
        }

    }
    private static class BCryptMatchesTestClass implements BiFunction<String, String, Boolean> {

        @Override
        public Boolean apply(String rawPassword, String encodedPassword) {
            BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
            return encoder.matches(rawPassword, encodedPassword);
        }

    }

    private static class SCryptEncodeTestClass implements Function<String, String> {

        @Override
        public String apply(String s) {
            SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();
            return encoder.encode(s);
        }
    }

    private static class SCryptMatchesTestClass implements BiFunction<String, String, Boolean> {

        @Override
        public Boolean apply(String rawPassword, String encodedPassword) {
            SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();
            return encoder.matches(rawPassword, encodedPassword);
        }
    }

    private static class SCryptInterfaceEncodeTestClass implements Function<String, String> {

        @Override
        public String apply(String rawPassword) {
            PasswordEncoder passwordEncoder = new SCryptPasswordEncoder();
            return passwordEncoder.encode(rawPassword);
        }
    }

    private static class SCryptInterfaceMatchesTestClass implements BiFunction<String, String, Boolean> {

        @Override
        public Boolean apply(String rawPassword, String encodedPassword) {
            PasswordEncoder encoder = new SCryptPasswordEncoder();
            return encoder.matches(rawPassword, encodedPassword);
        }
    }
}
