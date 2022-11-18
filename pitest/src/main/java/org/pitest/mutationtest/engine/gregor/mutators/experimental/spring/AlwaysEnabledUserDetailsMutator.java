package org.pitest.mutationtest.engine.gregor.mutators.experimental.spring;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.pitest.mutationtest.engine.MutationIdentifier;
import org.pitest.mutationtest.engine.gregor.MethodInfo;
import org.pitest.mutationtest.engine.gregor.MethodMutatorFactory;
import org.pitest.mutationtest.engine.gregor.MutationContext;

import java.util.HashSet;
import java.util.Set;

public enum AlwaysEnabledUserDetailsMutator implements MethodMutatorFactory {

    ALWAYS_ENABLED_USER_DETAILS_MUTATOR;

    @Override
    public MethodVisitor create(MutationContext context, MethodInfo methodInfo, MethodVisitor methodVisitor) {
        return new AlwaysEnabledUserDetailsMethodVisitor(this, context, methodVisitor);
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
        return "ALWAYS_ENABLED_USER_DETAILS_MUTATOR";
    }

    private static final class AlwaysEnabledUserDetailsMethodVisitor extends MethodVisitor {

        private static final Set<String> SUPPORTED_METHODS = new HashSet<>();
        private final MethodMutatorFactory factory;
        private final MutationContext context;

        static {
            SUPPORTED_METHODS.add("isAccountNonExpired");
            SUPPORTED_METHODS.add("isAccountNonLocked");
            SUPPORTED_METHODS.add("isCredentialsNonExpired");
            SUPPORTED_METHODS.add("isEnabled");
        }
        private AlwaysEnabledUserDetailsMethodVisitor(MethodMutatorFactory factory, MutationContext context, MethodVisitor methodVisitor) {
            super(Opcodes.ASM6, methodVisitor);
            this.factory = factory;
            this.context = context;
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
            if (owner.equals("org/springframework/security/core/userdetails/UserDetails")
                    && SUPPORTED_METHODS.contains(name)
                    && opcode == Opcodes.INVOKEINTERFACE
                    && desc.equals("()Z")
                    && itf) {
                final MutationIdentifier newId = context.registerMutation(factory,
                        String.format("Replacing UserDetails#%s result with true", name));
                if (context.shouldMutate(newId)) {
                    mv.visitInsn(Opcodes.ICONST_1);
                    return;
                }
            }
            mv.visitMethodInsn(opcode, owner, name, desc, itf);
        }
    }
}
