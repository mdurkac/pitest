package org.pitest.mutationtest.engine.gregor.mutators.experimental.md5;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.ArrayUtils;
import org.junit.Test;
import org.pitest.verifier.mutants.MutatorVerifierStart;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.function.Function;

import static org.pitest.mutationtest.engine.gregor.mutators.experimental.WeakDigestMutator.EXPERIMENTAL_WEAK_DIGEST;

public class WeakDigestSha3384MutatorTest {

    MutatorVerifierStart v = MutatorVerifierStart.forMutator(EXPERIMENTAL_WEAK_DIGEST)
            .notCheckingUnMutatedValues();

    @Test
    public void stringSha() {
        String input = "hello";
        v.forFunctionClass(StringMd5TestClass.class)
                .firstMutantShouldReturn(input, ArrayUtils.toObject(DigestUtils.md5(input)));
    }

    @Test
    public void inputStreamSha() throws IOException {
        v.forFunctionClass(InputStreamMd5TestClass.class)
                .firstMutantShouldReturn(new ByteArrayInputStream("hello".getBytes()),
                        ArrayUtils.toObject(DigestUtils.md5(new ByteArrayInputStream("hello".getBytes()))));
    }

    @Test
    public void bytesSha() {
        byte[] input = "hello".getBytes();
        v.forFunctionClass(BytesMd5TestClass.class)
                .firstMutantShouldReturn(ArrayUtils.toObject(input), ArrayUtils.toObject(DigestUtils.md5(input)));
    }

    @Test
    public void stringShaHex() {
        String input = "hello";
        v.forFunctionClass(StringMd5HexTestClass.class)
                .firstMutantShouldReturn(input, DigestUtils.md5Hex(input));
    }

    @Test
    public void inputStreamShaHex() throws IOException {
        v.forFunctionClass(InputStreamMd5HexTestClass.class)
                .firstMutantShouldReturn(new ByteArrayInputStream("hello".getBytes()),
                        DigestUtils.md5Hex(new ByteArrayInputStream("hello".getBytes())));
    }

    @Test
    public void bytesShaHex() {
        byte[] input = "hello".getBytes();
        v.forFunctionClass(BytesMd5HexTestClass.class)
                .firstMutantShouldReturn(ArrayUtils.toObject(input), DigestUtils.md5Hex(input));
    }

    @Test
    public void stringShaHexLambda() {
        String input = "hello";
        v.forFunctionClass(StringMd5LambdaTestClass.class)
                .firstMutantShouldReturn(input, DigestUtils.md5Hex(input));
    }

    private static class StringMd5LambdaTestClass implements Function<String, String> {
        @Override
        public String apply(String s) {
            Function<String, String> function = DigestUtils::sha3_384Hex;
            return function.apply(s);
        }
    }

    private static class StringMd5TestClass implements Function<String, Byte[]> {

        @Override
        public Byte[] apply(String s) {
            return ArrayUtils.toObject(DigestUtils.sha3_384(s));
        }
    }

    private static class InputStreamMd5TestClass implements Function<InputStream, Byte[]> {

        @Override
        public Byte[] apply(InputStream inputStream) {
            try {
                return ArrayUtils.toObject(DigestUtils.sha3_384(inputStream));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static class BytesMd5TestClass implements Function<Byte[], Byte[]> {

        @Override
        public Byte[] apply(Byte[] bytes) {
            return ArrayUtils.toObject(DigestUtils.sha3_384(ArrayUtils.toPrimitive(bytes)));
        }
    }

    private static class StringMd5HexTestClass implements Function<String, String> {

        @Override
        public String apply(String s) {
            return DigestUtils.sha3_384Hex(s);
        }
    }

    private static class InputStreamMd5HexTestClass implements Function<InputStream, String> {

        @Override
        public String apply(InputStream data) {
            try {
                return DigestUtils.sha3_384Hex(data);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static class BytesMd5HexTestClass implements Function<Byte[], String> {

        @Override
        public String apply(Byte[] bytes) {
            return DigestUtils.sha3_384Hex(ArrayUtils.toPrimitive(bytes));
        }
    }
}
