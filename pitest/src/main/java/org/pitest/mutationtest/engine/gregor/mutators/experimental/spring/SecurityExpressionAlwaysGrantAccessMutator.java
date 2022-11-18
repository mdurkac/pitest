package org.pitest.mutationtest.engine.gregor.mutators.experimental.spring;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.pitest.mutationtest.engine.MutationIdentifier;
import org.pitest.mutationtest.engine.gregor.MethodInfo;
import org.pitest.mutationtest.engine.gregor.MethodMutatorFactory;
import org.pitest.mutationtest.engine.gregor.MutationContext;

import java.util.HashSet;
import java.util.Set;

public enum SecurityExpressionAlwaysGrantAccessMutator implements MethodMutatorFactory {

    SECURITY_EXPRESSION_ALWAYS_GRANT_ACCESS_MUTATOR;

    @Override
    public MethodVisitor create(MutationContext context, MethodInfo methodInfo, MethodVisitor methodVisitor) {
        return new SecurityExpressionAlwaysGrantAccessMethodVisitor(this, context, methodVisitor);
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
        return "SECURITY_EXPRESSION_ALWAYS_GRANT_ACCESS_MUTATOR";
    }

    private static final class SecurityExpressionAlwaysGrantAccessMethodVisitor extends MethodVisitor {

        private static final Set<String> SUPPORTED_METHODS = new HashSet<>();
        private final MethodMutatorFactory factory;
        private final MutationContext context;

        static {
            SUPPORTED_METHODS.add("hasAuthority(Ljava/lang/String;)Z");
            SUPPORTED_METHODS.add("hasAnyAuthority([Ljava/lang/String;)Z");
            SUPPORTED_METHODS.add("hasRole(Ljava/lang/String;)Z");
            SUPPORTED_METHODS.add("hasAnyRole([Ljava/lang/String;)Z");
            SUPPORTED_METHODS.add("isAuthenticated()Z");
            SUPPORTED_METHODS.add("isRememberMe()Z");
            SUPPORTED_METHODS.add("isFullyAuthenticated()Z");
            SUPPORTED_METHODS.add("hasPermission(Ljava/lang/Object;Ljava/lang/Object;)Z");
            SUPPORTED_METHODS.add("hasPermission(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;)Z");
        }

        private SecurityExpressionAlwaysGrantAccessMethodVisitor(MethodMutatorFactory factory, MutationContext context, MethodVisitor methodVisitor) {
            super(Opcodes.ASM6, methodVisitor);
            this.factory = factory;
            this.context = context;
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
            if (owner.equals("org/springframework/security/access/expression/SecurityExpressionRoot")
                    && SUPPORTED_METHODS.contains(name + desc)) {
                final MutationIdentifier newId = context.registerMutation(factory,
                        String.format("Replacing SecurityExpressionRoot#%s result with true", name));
                if (context.shouldMutate(newId)) {
                    mv.visitInsn(Opcodes.ICONST_1);
                    return;
                }
            }
            mv.visitMethodInsn(opcode, owner, name, desc, itf);
        }
    }
}
