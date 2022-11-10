package org.pitest.mutationtest.engine.gregor.mutators.experimental;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.pitest.mutationtest.engine.MutationIdentifier;
import org.pitest.mutationtest.engine.gregor.MethodInfo;
import org.pitest.mutationtest.engine.gregor.MethodMutatorFactory;
import org.pitest.mutationtest.engine.gregor.MutationContext;

import java.util.HashSet;
import java.util.Set;

public enum NoOpPasswordEncoderMutator implements MethodMutatorFactory {

    NOOP_PASSWORD_ENCODER_MUTATOR;

    @Override
    public MethodVisitor create(MutationContext context, MethodInfo methodInfo, MethodVisitor methodVisitor) {
        return new NoOpPasswordEncoderMethodVisitor(this, context, methodVisitor);
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
        return "NOOP_PASSWORD_ENCODER_MUTATOR";
    }

    private static final class NoOpPasswordEncoderMethodVisitor extends MethodVisitor {

        private static final String NOOP_OWNER = "org/springframework/security/crypto/password/NoOpPasswordEncoder";
        private static final String PASSWORD_ENCODER_OWNER = "org/springframework/security/crypto/password/PasswordEncoder";

        private static final Set<String> ENCODER_OWNERS = new HashSet<>();
        private final MethodMutatorFactory factory;
        private final MutationContext context;

        static {
            ENCODER_OWNERS.add(PASSWORD_ENCODER_OWNER);
            ENCODER_OWNERS.add("org/springframework/security/crypto/bcrypt/BCryptPasswordEncoder");
            ENCODER_OWNERS.add("org/springframework/security/crypto/password/AbstractPasswordEncoder");
            ENCODER_OWNERS.add("org/springframework/security/crypto/argon2/Argon2PasswordEncoder");
            ENCODER_OWNERS.add("org/springframework/security/crypto/password/DelegatingPasswordEncoder");
            ENCODER_OWNERS.add("org/springframework/security/crypto/password/LdapShaPasswordEncoder");
            ENCODER_OWNERS.add("org/springframework/security/crypto/password/Md4PasswordEncoder");
            ENCODER_OWNERS.add("org/springframework/security/crypto/password/MessageDigestPasswordEncoder");
            ENCODER_OWNERS.add("org/springframework/security/crypto/password/Pbkdf2PasswordEncoder");
            ENCODER_OWNERS.add("org/springframework/security/crypto/scrypt/SCryptPasswordEncoder");
            ENCODER_OWNERS.add("org/springframework/security/crypto/password/StandardPasswordEncoder");
        }

        private NoOpPasswordEncoderMethodVisitor(MethodMutatorFactory factory, MutationContext context, MethodVisitor methodVisitor) {
            super(Opcodes.ASM6, methodVisitor);
            this.factory = factory;
            this.context = context;
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name,
                                    String desc, boolean itf) {
            if (ENCODER_OWNERS.contains(owner)) {
                if (name.equals("encode") && desc.equals("(Ljava/lang/CharSequence;)Ljava/lang/String;")) {
                    final MutationIdentifier newId = context.registerMutation(factory,
                            String.format("Replaced %s#encode with NoopPasswordEncoder#encode.",owner));
                    if (context.shouldMutate(newId)) {
                        mutateEncode();
                        return;
                    }
                }
                if (name.equals("matches") && desc.equals("(Ljava/lang/CharSequence;Ljava/lang/String;)Z")) {
                    final MutationIdentifier newId = context.registerMutation(factory,
                            String.format("Replaced %s#matches with NoopPasswordEncoder#matches.",owner));
                    if (context.shouldMutate(newId)) {
                        mutateMatches();
                        return;
                    }
                }
            }
            mv.visitMethodInsn(opcode, owner, name, desc, itf);
        }

        private void mutateEncode() {
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, NOOP_OWNER, "getInstance",
                    "()Lorg/springframework/security/crypto/password/PasswordEncoder;", false);

            mv.visitInsn(Opcodes.SWAP);

            mv.visitMethodInsn(Opcodes.INVOKEINTERFACE, PASSWORD_ENCODER_OWNER, "encode",
                    "(Ljava/lang/CharSequence;)Ljava/lang/String;", true);
        }

        private void mutateMatches() {
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, NOOP_OWNER, "getInstance",
                    "()Lorg/springframework/security/crypto/password/PasswordEncoder;", false);

            mv.visitInsn(Opcodes.DUP_X2);

            mv.visitInsn(Opcodes.POP);

            mv.visitMethodInsn(Opcodes.INVOKEINTERFACE, PASSWORD_ENCODER_OWNER, "matches",
                    "(Ljava/lang/CharSequence;Ljava/lang/String;)Z", true);
        }
    }
}
