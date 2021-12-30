package io.xlogistx.common.task;

import java.util.function.Consumer;
import java.util.function.Supplier;

public interface CallbackTask<T, S>
        extends Consumer<T>, Supplier<S>
{
    void exception(Exception e);
}
