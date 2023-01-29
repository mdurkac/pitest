package org.pitest.mutationtest.engine.gregor.mutators.experimental.spring;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.pitest.mutationtest.engine.MutationIdentifier;
import org.pitest.mutationtest.engine.gregor.MethodInfo;
import org.pitest.mutationtest.engine.gregor.MethodMutatorFactory;
import org.pitest.mutationtest.engine.gregor.MutationContext;

public enum PermitAllOnUrlRequiringAuthenticationMutator implements MethodMutatorFactory {
    PERMIT_ALL_ON_URL_REQUIRING_AUTHENTICATION_MUTATOR;

    @Override
    public MethodVisitor create(MutationContext context, MethodInfo methodInfo, MethodVisitor methodVisitor) {
        return new PermitAllOnUrlRequiringAuthenticationMethodVisitor(this, context, methodVisitor);
    }

    @Override
    public String getGloballyUniqueId() {
        return this.getClass().getName();
    }

    @Override
    public String getName() {
        return toString();
    }

    @Override
    public String toString() {
        return "PERMIT_ALL_ON_AUTHENTICATED_MUTATOR";
    }

    private static final class PermitAllOnUrlRequiringAuthenticationMethodVisitor extends MethodVisitor {

        private final MethodMutatorFactory factory;
        private final MutationContext context;

        private PermitAllOnUrlRequiringAuthenticationMethodVisitor(MethodMutatorFactory factory, MutationContext context, MethodVisitor methodVisitor) {
            super(Opcodes.ASM6, methodVisitor);
            this.factory = factory;
            this.context = context;
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
            if (owner.equals("org/springframework/security/config/annotation/web/configurers/ExpressionUrlAuthorizationConfigurer$AuthorizedUrl")
                    && name.equals("authenticated")
                    && opcode == Opcodes.INVOKEVIRTUAL
                    && desc.equals("()Lorg/springframework/security/config/annotation/web/configurers/ExpressionUrlAuthorizationConfigurer$ExpressionInterceptUrlRegistry;")
                    && !itf) {
                final MutationIdentifier newId = context.registerMutation(factory, "Replacing Authentication#isAuthenticated result with true");
                if (context.shouldMutate(newId)) {
                    mv.visitMethodInsn(
                            Opcodes.INVOKEVIRTUAL,
                            "org/springframework/security/config/annotation/web/configurers/ExpressionUrlAuthorizationConfigurer$AuthorizedUrl",
                            "permitAll",
                            "()Lorg/springframework/security/config/annotation/web/configurers/ExpressionUrlAuthorizationConfigurer$ExpressionInterceptUrlRegistry;",
                            false);
                    return;
                }
            }
            mv.visitMethodInsn(opcode, owner, name, desc, itf);
        }
    }
}
