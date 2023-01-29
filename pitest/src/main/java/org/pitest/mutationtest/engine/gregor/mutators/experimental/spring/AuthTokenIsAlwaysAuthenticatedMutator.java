package org.pitest.mutationtest.engine.gregor.mutators.experimental.spring;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.pitest.mutationtest.engine.MutationIdentifier;
import org.pitest.mutationtest.engine.gregor.MethodInfo;
import org.pitest.mutationtest.engine.gregor.MethodMutatorFactory;
import org.pitest.mutationtest.engine.gregor.MutationContext;

public enum AuthTokenIsAlwaysAuthenticatedMutator implements MethodMutatorFactory {

    AUTH_TOKEN_IS_ALWAYS_AUTHENTICATED_MUTATOR;

    @Override
    public MethodVisitor create(MutationContext context, MethodInfo methodInfo, MethodVisitor methodVisitor) {
        return new AuthTokenIsAlwaysAuthenticatedMethodVisitor(this, context, methodVisitor);
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
        return "AUTH_TOKEN_IS_ALWAYS_AUTHENTICATED_MUTATOR";
    }

    private static final class AuthTokenIsAlwaysAuthenticatedMethodVisitor extends MethodVisitor {

        private final MethodMutatorFactory factory;
        private final MutationContext context;

        private AuthTokenIsAlwaysAuthenticatedMethodVisitor(MethodMutatorFactory factory, MutationContext context, MethodVisitor methodVisitor) {
            super(Opcodes.ASM6, methodVisitor);
            this.factory = factory;
            this.context = context;
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
            if (owner.equals("org/springframework/security/core/Authentication")
                    && name.equals("isAuthenticated")
                    && opcode == Opcodes.INVOKEINTERFACE
                    && desc.equals("()Z")
                    && itf) {
                final MutationIdentifier newId = context.registerMutation(factory, "Replacing Authentication#isAuthenticated result with true");
                if (context.shouldMutate(newId)) {
                    mv.visitInsn(Opcodes.ICONST_1);
                    return;
                }
            }
            mv.visitMethodInsn(opcode, owner, name, desc, itf);
        }
    }
}
