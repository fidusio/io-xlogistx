package io.xlogistx.common.fsm;

import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.task.SupplierConsumerTask;
import org.zoxweb.server.task.TaskSchedulerProcessor;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.util.SharedUtil;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;

public class SimpleStateMachine<C>
    implements StateMachineInt<C>
{

    public final static LogWrapper log = new LogWrapper(SimpleStateMachine.class).setEnabled(false);
    private final String name;
    private final TaskSchedulerProcessor tsp;
    private final Map<String, TriggerConsumerInt<?>> tcMap = new LinkedHashMap();
    private final Map<String, StateInt> states = new LinkedHashMap<String, StateInt>();
    private C config;
    private final Executor executor;
    private volatile boolean isClosed = false;

    private final AtomicReference<StateInt> currentState = new AtomicReference<>();


    public SimpleStateMachine(String name)
    {
        this(name, TaskUtil.getDefaultTaskScheduler());
    }

    public SimpleStateMachine(String name, TaskSchedulerProcessor taskSchedulerProcessor)
            throws NullPointerException
    {
        SharedUtil.checkIfNulls("Name or TaskScheduler can't be null.", name, taskSchedulerProcessor);
        this.name = name;
        this.tsp = taskSchedulerProcessor;
        //this.schedulerOnly = schedulerOnly;
        executor = tsp.getExecutor();
    }

    public SimpleStateMachine(String name, Executor executor)
            throws NullPointerException
    {
        if(log.isEnabled()) log.getLogger().info(name + ":" + executor);
        SharedUtil.checkIfNulls("Name or Executor can't be null.", name);
        this.name = name;
        this.tsp = null;
        this.executor = executor;
    }

    @Override
    public synchronized StateMachineInt<C> register(StateInt state)
    {
        if(state != null)
        {
            TriggerConsumerInt<?>[] triggers = state.triggers();
            if(triggers != null)
            {
                for(TriggerConsumerInt<?> tc: triggers)
                {
                    mapTriggerConsumer(tc);
                }
            }
            state.setStateMachine(this);
            states.put(state.getName(), state);
        }
        return this;
    }

    private void mapTriggerConsumer(TriggerConsumerInt<?> tc)
    {
        String canonicalIDs[] = tc.canonicalIDs();
        for (String canID : canonicalIDs)
        {
            tcMap.put(canID, tc);
        }
    }



    @Override
    public StateMachineInt publish(TriggerInt trigger)
    {
        if(isClosed())
            throw new IllegalStateException("State machine closed");

        TriggerConsumerInt<?> tc = tcMap.get(trigger.getCanonicalID());
        if(tc != null)
        {
            if(log.isEnabled()) log.getLogger().info("" + trigger);
            if(isScheduledTaskEnabled())
                tsp.queue(0, new SupplierConsumerTask(trigger, new TriggerConsumerHolder<>(tc)));
            else
            {
                    SupplierConsumerTask sct = new SupplierConsumerTask(trigger, new TriggerConsumerHolder<>(tc));
                    if(executor != null)
                        executor.execute(sct);
                    else
                        sct.run();
            };
        }
        return this;
    }


    @Override
    public StateMachineInt publishSync(TriggerInt trigger)
    {
        if(isClosed())
            throw new IllegalStateException("State machine closed");

        TriggerConsumerInt<?> tc = tcMap.get(trigger.getCanonicalID());
        if(tc != null)
        {
            if(log.isEnabled()) log.getLogger().info("" + trigger);


                SupplierConsumerTask sct = new SupplierConsumerTask(trigger, new TriggerConsumerHolder<>(tc));
                sct.run();
        }
        return this;
    }

    @Override
    public StateMachineInt publishToCurrentState(TriggerInt trigger) {
        if(isClosed())
            throw new IllegalStateException("State machine closed");

        StateInt current = getCurrentState();
        if(current == null)
        {
            return publish(trigger);
        }
        else
        {
            TriggerConsumerInt<?> tci = current.lookupTriggerConsumer(trigger.getCanonicalID());
            if (tci != null) {
                SupplierConsumerTask sct =  new SupplierConsumerTask(trigger, new TriggerConsumerHolder<>(tci));
                if (isScheduledTaskEnabled())
                    tsp.queue(0, sct);
                else if(executor != null)
                    executor.execute(sct);
                else
                    sct.run();

            }
        }
        return this;
    }

    @Override
    public C getConfig()
    {
        return config;
    }

    @Override
    public StateMachineInt setConfig(C config)
    {
        this.config = config;
        return this;
    }

    @Override
    public String getName()
    {
        return name;
    }

    public void start(boolean sync)
    {
        if (tcMap.get(StateInt.States.INIT.getName()) != null) {
            if (sync)
                publishSync(new Trigger<Void>(this, StateInt.States.INIT, null, null));
            else
                publish(new Trigger<Void>(this, StateInt.States.INIT, null, null));
        }
        else
            throw new IllegalArgumentException("Not Init state");
    }


    public String toString()
    {
        return getName();
    }

    public TaskSchedulerProcessor getScheduler()
    {
        return tsp;
    }

    @Override
    public Executor getExecutor()
    {
        return executor;
    }

    @Override
    public boolean isScheduledTaskEnabled()
    {
        return tsp != null;
    }

    @Override
    public StateInt lookupState(String name)
    {
        return states.get(name);
    }

    @Override
    public StateInt lookupState(Enum<?> name)
    {
        return lookupState(SharedUtil.enumName(name));
    }

    @Override
    public StateInt getCurrentState() {
        return currentState.get();
    }

    @Override
    public void setCurrentState(StateInt stateInt) {
        currentState.set(stateInt);
    }



    @Override
    public synchronized void close()
    {
        if(!isClosed)
            isClosed = true;
    }

    public boolean isClosed()
    {
        return isClosed;
    }


}
