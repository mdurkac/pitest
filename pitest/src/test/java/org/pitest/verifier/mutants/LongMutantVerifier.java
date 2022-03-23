package org.pitest.verifier.mutants;

import org.pitest.mutationtest.engine.Mutant;
import org.pitest.mutationtest.engine.MutationDetails;
import org.pitest.mutationtest.engine.gregor.GregorMutater;
import org.pitest.util.Unchecked;

import java.lang.reflect.Constructor;
import java.util.Collection;
import java.util.List;
import java.util.function.LongFunction;
import java.util.function.LongSupplier;
import java.util.function.Predicate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verification based on instantiating mutated versions of a class.
 * <p>
 * Classes must implement java.util.IntFunction and provide a default
 * constructor.
 */
public class LongMutantVerifier<B> extends MutatorVerifier {

    private final GregorMutater engine;
    private final Class<? extends LongFunction<B>> target;

    public LongMutantVerifier(GregorMutater engine, Class<? extends LongFunction<B>> target, Predicate<MutationDetails> filter) {
        super(engine, target, filter);
        this.engine = engine;
        this.target = target;
    }

    /**
     * Suppliers allow consumable inputs (eg streams) can be reused
     */
    public void firstMutantShouldReturn(LongSupplier input, B expected) {
        assertThat(runWithoutMutation(input.getAsLong()))
                .describedAs("Expected unmutated code to return different value to mutated code")
                .isNotEqualTo(expected);

        List<MutationDetails> mutations = findMutations();
        assertThat(mutateAndCall(input.getAsLong(), getFirstMutant(mutations)))
                .isEqualTo(expected);
    }

    private B runWithoutMutation(long input) {
        return this.runInClassLoader(target.getClassLoader(), input);
    }

    private B mutateAndCall(long input, Mutant mutant) {
        ClassLoader loader = this.createClassLoader(mutant);
        return this.runInClassLoader(loader, input);
    }

    private B runInClassLoader(ClassLoader loader, long input) {
        try {
            Class<?> forLoader = loader.loadClass(target.getName());

            Constructor c = forLoader.getDeclaredConstructor();
            c.setAccessible(true);
            LongFunction<B> instance = (LongFunction<B>) c.newInstance();
            return instance.apply(input);
        } catch (ReflectiveOperationException ex) {
            throw Unchecked.translateCheckedException(ex);
        }
    }

    protected Mutant getFirstMutant(final Collection<MutationDetails> actual) {
        assertThat(actual)
                .describedAs("Expecting at least one mutant to be generated")
                .isNotEmpty();
        final Mutant mutant = this.engine.getMutation(actual.iterator().next()
                .getId());
        verifyMutant(mutant);
        return mutant;
    }

}
