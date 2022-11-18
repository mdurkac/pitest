package org.pitest.mutationtest.engine.gregor.mutators.experimental;

import org.junit.Test;
import org.pitest.verifier.mutants.MutatorVerifierStart;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.TestingAuthenticationToken;

import java.util.concurrent.Callable;
import java.util.function.Function;

import static org.pitest.mutationtest.engine.gregor.mutators.experimental.SecurityExpressionAlwaysGrantAccessMutator.SECURITY_EXPRESSION_ALWAYS_GRANT_ACCESS_MUTATOR;

public class SecurityExpressionAlwaysGrantAccessMutatorTest {

    MutatorVerifierStart verifier = MutatorVerifierStart
            .forMutator(SECURITY_EXPRESSION_ALWAYS_GRANT_ACCESS_MUTATOR)
            .notCheckingUnMutatedValues();

    @Test
    public void isAuthenticatedTest() {
        verifier.forCallableClass(IsAuthenticatedTestClass.class)
                .firstMutantShouldReturn(true);
    }

    @Test
    public void isRememberMeTest() {
        verifier.forCallableClass(IsRememberMeTestClass.class)
                .firstMutantShouldReturn(true);
    }

    @Test
    public void isFullyAuthenticatedTest() {
        verifier.forCallableClass(IsFullyAuthenticatedTestClass.class)
                .firstMutantShouldReturn(true);
    }

    @Test
    public void hasRoleTest() {
        verifier.forFunctionClass(HasRoleTestClass.class)
                .firstMutantShouldReturn("ROLE", true);
    }

    @Test
    public void hasAnyRoleTest() {
        verifier.forFunctionClass(HasAnyRoleTestClass.class)
                .firstMutantShouldReturn(new String[] {"ROLE1", "ROLE2"}, true);
    }

    @Test
    public void hasAuthorityTest() {
        verifier.forCallableClass(HasAuthorityTestClass.class)
                .firstMutantShouldReturn(true);
    }

    @Test
    public void hasAnyAuthorityTest() {
        verifier.forCallableClass(HasAnyAuthorityTestClass.class)
                .firstMutantShouldReturn(true);
    }

    @Test
    public void hasPermission() {
        verifier.forCallableClass(HasPermissionTestClass.class)
                .firstMutantShouldReturn(true);
    }

    @Test
    public void hasPermissionWithType() {
        verifier.forCallableClass(HasPermissionWithTypeTestClass.class)
                .firstMutantShouldReturn(true);
    }

    private static final class IsAuthenticatedTestClass implements Callable<Boolean> {

        @Override
        public Boolean call() {
            SecurityExpressionRoot securityExpressionRoot = getSecurityExpressionRoot();
            return securityExpressionRoot.isAuthenticated();
        }
    }

    private static final class IsRememberMeTestClass implements Callable<Boolean> {

        @Override
        public Boolean call() {
            SecurityExpressionRoot securityExpressionRoot = getSecurityExpressionRoot();
            return securityExpressionRoot.isRememberMe();
        }
    }

    private static final class IsFullyAuthenticatedTestClass implements Callable<Boolean> {

        @Override
        public Boolean call() {
            SecurityExpressionRoot securityExpressionRoot = getSecurityExpressionRoot();
            return securityExpressionRoot.isFullyAuthenticated();
        }
    }

    private static final class HasAuthorityTestClass implements Callable<Boolean> {

        @Override
        public Boolean call() {
            SecurityExpressionRoot securityExpressionRoot = getSecurityExpressionRoot();
            return securityExpressionRoot.hasAuthority("AUTHORITY");
        }
    }

    private static final class HasAnyAuthorityTestClass implements Callable<Boolean> {

        @Override
        public Boolean call() {
            SecurityExpressionRoot securityExpressionRoot = getSecurityExpressionRoot();
            return securityExpressionRoot.hasAnyAuthority("AUTHORITY1", "AUTHORITY2");
        }
    }

    private static final class HasPermissionTestClass implements Callable<Boolean> {

        @Override
        public Boolean call() {
            SecurityExpressionRoot securityExpressionRoot = getSecurityExpressionRoot();
            return securityExpressionRoot.hasPermission("target", "permission");
        }
    }

    private static final class HasPermissionWithTypeTestClass implements Callable<Boolean> {

        @Override
        public Boolean call() {
            SecurityExpressionRoot securityExpressionRoot = getSecurityExpressionRoot();
            return securityExpressionRoot.hasPermission("target", "type", "permission");
        }
    }

    private static final class HasRoleTestClass implements Function<String, Boolean> {

        @Override
        public Boolean apply(String role) {
            SecurityExpressionRoot securityExpressionRoot = getSecurityExpressionRoot();
            return securityExpressionRoot.hasRole(role);
        }
    }

    private static final class HasAnyRoleTestClass implements Function<String[], Boolean> {

        @Override
        public Boolean apply(String[] roles) {
            SecurityExpressionRoot securityExpressionRoot = getSecurityExpressionRoot();
            return securityExpressionRoot.hasAnyRole(roles);
        }
    }

    private static SecurityExpressionRoot getSecurityExpressionRoot() {
        return new SecurityExpressionRoot(new TestingAuthenticationToken("principal", "credentials")) {
            @Override
            public Object getPrincipal() {
                return super.getPrincipal();
            }

            @Override
            public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
            }

            @Override
            public void setRoleHierarchy(RoleHierarchy roleHierarchy) {
            }

            @Override
            public void setDefaultRolePrefix(String defaultRolePrefix) {
            }

            @Override
            public boolean hasPermission(Object target, Object permission) {
                return false;
            }

            @Override
            public boolean hasPermission(Object targetId, String targetType, Object permission) {
                return false;
            }

            @Override
            public void setPermissionEvaluator(PermissionEvaluator permissionEvaluator) {
            }
        };
    }
}
