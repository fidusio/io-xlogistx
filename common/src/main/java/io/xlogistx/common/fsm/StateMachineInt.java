package io.xlogistx.common.fsm;

import org.zoxweb.server.task.TaskSchedulerProcessor;
import org.zoxweb.shared.util.GetName;

import java.util.concurrent.Executor;


public interface StateMachineInt<C>
extends GetName, AutoCloseable
{

    StateMachineInt register(StateInt state);

    StateMachineInt publish(TriggerInt trigger);

    C getConfig();
    StateMachineInt setConfig(C config);

    void start();

    void close();

    TaskSchedulerProcessor getScheduler();
    Executor getExecutor();
    StateInt lookupState(String name);
    StateInt lookupState(GetName name);
}
