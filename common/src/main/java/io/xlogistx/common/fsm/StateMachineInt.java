package io.xlogistx.common.fsm;

import org.zoxweb.server.task.TaskSchedulerProcessor;
import org.zoxweb.shared.util.GetName;



public interface StateMachineInt
extends GetName, AutoCloseable
{

    StateMachineInt register(StateInt state);

    StateMachineInt publish(TriggerInt trigger);

    void start();

    void close();

    TaskSchedulerProcessor getTSP();
}
