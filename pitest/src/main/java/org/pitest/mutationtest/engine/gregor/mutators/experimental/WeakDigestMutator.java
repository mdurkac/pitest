package org.pitest.mutationtest.engine.gregor.mutators.experimental;

import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.pitest.mutationtest.engine.MutationIdentifier;
import org.pitest.mutationtest.engine.gregor.MethodInfo;
import org.pitest.mutationtest.engine.gregor.MethodMutatorFactory;
import org.pitest.mutationtest.engine.gregor.MutationContext;

import java.util.HashMap;
import java.util.Map;

public enum WeakDigestMutator implements MethodMutatorFactory {

    EXPERIMENTAL_WEAK_DIGEST;

    @Override
    public MethodVisitor create(MutationContext context, MethodInfo methodInfo, MethodVisitor methodVisitor) {
        return new WeakDigestMutatorMethodVisitor(this, context, methodVisitor);
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
        return "EXPERIMENTAL_WEAK_DIGEST";
    }

    private static final class WeakDigestMutatorMethodVisitor extends MethodVisitor {

        private static final String EXPECTED_OWNER_APACHE_COMMONS_DIGEST_UTILS = "org/apache/commons/codec/digest/DigestUtils";
        private static final Map<String, Replacement> REPLACEMENTS;
        private final MethodMutatorFactory factory;
        private final MutationContext context;


        private WeakDigestMutatorMethodVisitor(MethodMutatorFactory factory, MutationContext context, MethodVisitor methodVisitor) {
            super(Opcodes.ASM6, methodVisitor);
            this.factory = factory;
            this.context = context;
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String descriptor,
                                    boolean isInterface) {
            Replacement replacement = REPLACEMENTS.get(name + descriptor);
            if (owner.equals(EXPECTED_OWNER_APACHE_COMMONS_DIGEST_UTILS)
                    && replacement != null && opcode == Opcodes.INVOKESTATIC) {
                MutationIdentifier identifier = context.registerMutation(factory, replacement.toString());
                if (context.shouldMutate(identifier)) {
                    this.mv.visitMethodInsn(opcode, owner, replacement.destination, replacement.descriptor, false);
                    return;
                }
            }
            this.mv.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
        }

        @Override
        public void visitInvokeDynamicInsn(String name, String descriptor, Handle bootstrapMethodHandle,
                                           Object... bootstrapMethodArguments) {
            bootstrapMethodHandle = mutateHandle(bootstrapMethodHandle);
            Object[] methodArgs = new Object[bootstrapMethodArguments.length];
            for (int i = 0; i < bootstrapMethodArguments.length; i++) {
                Object bootstrapMethodArgument = bootstrapMethodArguments[i];
                if (bootstrapMethodArgument instanceof Handle) {
                    methodArgs[i] = mutateHandle((Handle) bootstrapMethodArgument);
                } else {
                    methodArgs[i] = bootstrapMethodArgument;
                }
            }
            super.visitInvokeDynamicInsn(name, descriptor, bootstrapMethodHandle, methodArgs);
        }

        private Handle mutateHandle(Handle handle) {
            int opcode = handle.getTag();
            String owner = handle.getOwner();
            String name = handle.getName();
            String descriptor = handle.getDesc();

            if (owner.equals(EXPECTED_OWNER_APACHE_COMMONS_DIGEST_UTILS) && opcode == Opcodes.H_INVOKESTATIC) {
                Replacement replacement = REPLACEMENTS.get(name + descriptor);
                if (replacement != null) {
                    if (replacement.descriptor.equals(descriptor)) {
                        MutationIdentifier id = context.registerMutation(factory, replacement.toString());
                        if (context.shouldMutate(id)) {
                            return new Handle(
                                    opcode,
                                    owner,
                                    replacement.destination,
                                    descriptor,
                                    handle.isInterface());
                        }
                    }
                }
            }
            return handle;
        }

        static {
            String byteToByte = "([B)[B";
            String byteToString = "([B)Ljava/lang/String;";
            String inputStreamToByte = "(Ljava/io/InputStream;)[B";
            String inputStreamToString = "(Ljava/io/InputStream;)Ljava/lang/String;";
            String stringToByte = "(Ljava/lang/String;)[B";
            String stringToString = "(Ljava/lang/String;)Ljava/lang/String;";

            REPLACEMENTS = new HashMap<>();
            put(new Replacement("sha256", "md5", byteToByte));
            put(new Replacement("sha256", "md5", inputStreamToByte));
            put(new Replacement("sha256", "md5", stringToByte));
            put(new Replacement("sha256Hex", "md5Hex", byteToString));
            put(new Replacement("sha256Hex", "md5Hex", inputStreamToString));
            put(new Replacement("sha256Hex", "md5Hex", stringToString));

            put(new Replacement("sha1", "md5", byteToByte));
            put(new Replacement("sha1", "md5", inputStreamToByte));
            put(new Replacement("sha1", "md5", stringToByte));
            put(new Replacement("sha1Hex", "md5Hex", byteToString));
            put(new Replacement("sha1Hex", "md5Hex", inputStreamToString));
            put(new Replacement("sha1Hex", "md5Hex", stringToString));

            put(new Replacement("sha3_224", "md5", byteToByte));
            put(new Replacement("sha3_224", "md5", inputStreamToByte));
            put(new Replacement("sha3_224", "md5", stringToByte));
            put(new Replacement("sha3_224Hex", "md5Hex", byteToString));
            put(new Replacement("sha3_224Hex", "md5Hex", inputStreamToString));
            put(new Replacement("sha3_224Hex", "md5Hex", stringToString));

            put(new Replacement("sha3_256", "md5", byteToByte));
            put(new Replacement("sha3_256", "md5", inputStreamToByte));
            put(new Replacement("sha3_256", "md5", stringToByte));
            put(new Replacement("sha3_256Hex", "md5Hex", byteToString));
            put(new Replacement("sha3_256Hex", "md5Hex", inputStreamToString));
            put(new Replacement("sha3_256Hex", "md5Hex", stringToString));

            put(new Replacement("sha3_384", "md5", byteToByte));
            put(new Replacement("sha3_384", "md5", inputStreamToByte));
            put(new Replacement("sha3_384", "md5", stringToByte));
            put(new Replacement("sha3_384Hex", "md5Hex", byteToString));
            put(new Replacement("sha3_384Hex", "md5Hex", inputStreamToString));
            put(new Replacement("sha3_384Hex", "md5Hex", stringToString));

            put(new Replacement("sha3_512", "md5", byteToByte));
            put(new Replacement("sha3_512", "md5", inputStreamToByte));
            put(new Replacement("sha3_512", "md5", stringToByte));
            put(new Replacement("sha3_512Hex", "md5Hex", byteToString));
            put(new Replacement("sha3_512Hex", "md5Hex", inputStreamToString));
            put(new Replacement("sha3_512Hex", "md5Hex", stringToString));

            put(new Replacement("sha384", "md5", byteToByte));
            put(new Replacement("sha384", "md5", inputStreamToByte));
            put(new Replacement("sha384", "md5", stringToByte));
            put(new Replacement("sha384Hex", "md5Hex", byteToString));
            put(new Replacement("sha384Hex", "md5Hex", inputStreamToString));
            put(new Replacement("sha384Hex", "md5Hex", stringToString));

            put(new Replacement("sha512_224", "md5", byteToByte));
            put(new Replacement("sha512_224", "md5", inputStreamToByte));
            put(new Replacement("sha512_224", "md5", stringToByte));
            put(new Replacement("sha512_224Hex", "md5Hex", byteToString));
            put(new Replacement("sha512_224Hex", "md5Hex", inputStreamToString));
            put(new Replacement("sha512_224Hex", "md5Hex", stringToString));

            put(new Replacement("sha512_256", "md5", byteToByte));
            put(new Replacement("sha512_256", "md5", inputStreamToByte));
            put(new Replacement("sha512_256", "md5", stringToByte));
            put(new Replacement("sha512_256Hex", "md5Hex", byteToString));
            put(new Replacement("sha512_256Hex", "md5Hex", inputStreamToString));
            put(new Replacement("sha512_256Hex", "md5Hex", stringToString));

            put(new Replacement("sha512", "md5", byteToByte));
            put(new Replacement("sha512", "md5", inputStreamToByte));
            put(new Replacement("sha512", "md5", stringToByte));
            put(new Replacement("sha512Hex", "md5Hex", byteToString));
            put(new Replacement("sha512Hex", "md5Hex", inputStreamToString));
            put(new Replacement("sha512Hex", "md5Hex", stringToString));
        }

        private static void put(Replacement replacement) {
            WeakDigestMutatorMethodVisitor.REPLACEMENTS.put(replacement.name + replacement.descriptor, replacement);
        }
    }

    private static final class Replacement {
        private final String name;
        private final String destination;
        private final String descriptor;

        private Replacement(String name, String destination, String descriptor) {
            this.name = name;
            this.destination = destination;
            this.descriptor = descriptor;
        }

        @Override
        public String toString() {
            String template = "Replaced DigestUtils::%s with DigestUtils::%s.";
            return String.format(template, name, destination);
        }
    }
}
