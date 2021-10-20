package io.xlogistx.common.fsm;

import org.zoxweb.server.task.SupplierConsumerTask;
import org.zoxweb.server.task.TaskSchedulerProcessor;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.util.GetName;
import org.zoxweb.shared.util.SharedUtil;

import java.util.*;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;

public class StateMachine<C>
    implements StateMachineInt<C>
{

    protected final static Logger log = Logger.getLogger(StateMachine.class.getName());
    private final String name;
    private final TaskSchedulerProcessor tsp;
    private Map<String, Set<TriggerConsumerInt<?>>> tcMap = new LinkedHashMap<String, Set<TriggerConsumerInt<?>>>();
    private Map<String, StateInt<?>> states = new LinkedHashMap<String, StateInt<?>>();
    private C config;
    final private Executor executor;
    private volatile boolean isClosed = false;

    AtomicReference<StateInt> currentState = new AtomicReference<StateInt>();


    public StateMachine(String name)
    {
        this(name, TaskUtil.getDefaultTaskScheduler());
    }

    public StateMachine(String name, TaskSchedulerProcessor taskSchedulerProcessor)
            throws NullPointerException
    {
        SharedUtil.checkIfNulls("Name or TaskScheduler can't be null.", name, taskSchedulerProcessor);
        this.name = name;
        this.tsp = taskSchedulerProcessor;
        //this.schedulerOnly = schedulerOnly;
        executor = tsp.getExecutor();
    }

    public StateMachine(String name, Executor executor)
            throws NullPointerException
    {
        log.info(name + ":" + executor);
        SharedUtil.checkIfNulls("Name or Executor can't be null.", name);
        this.name = name;
        this.tsp = null;
        this.executor = executor;
    }

    @Override
    public StateMachineInt register(StateInt state)
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

    private synchronized void mapTriggerConsumer(TriggerConsumerInt<?> tc)
    {
        String cids[] = tc.canonicalIDs();
        for (String canID : cids)
        {

            Set<TriggerConsumerInt<?>> tcSet = tcMap.get(canID);
            if (tcSet == null)
            {
                tcSet = new LinkedHashSet<TriggerConsumerInt<?>>();
                tcMap.put(canID, tcSet);
            }
            tcSet.add(tc);
        }
    }



    @Override
    public StateMachineInt publish(TriggerInt trigger)
    {
        if(isClosed())
            throw new IllegalStateException("State machine closed");

        Set<TriggerConsumerInt<?>> set = tcMap.get(trigger.getCanonicalID());
        if(set != null)
        {
            log.info("" + trigger);
            if(isScheduledTaskEnabled())
                set.forEach(c -> tsp.queue(0, new SupplierConsumerTask(trigger, new TriggerConsumerHolder<>(c))));
            else
                set.forEach(c -> {
                    SupplierConsumerTask sct = new SupplierConsumerTask(trigger, new TriggerConsumerHolder<>(c));
                    if(executor != null)
                        executor.execute(sct);
                    else
                        sct.run();
                });
        }
        return this;
    }


    @Override
    public StateMachineInt publishSync(TriggerInt trigger)
    {
        if(isClosed())
            throw new IllegalStateException("State machine closed");

        Set<TriggerConsumerInt<?>> set = tcMap.get(trigger.getCanonicalID());
        if(set != null)
        {
            log.info("" + trigger);

            set.forEach(c -> {
                SupplierConsumerTask sct = new SupplierConsumerTask(trigger, new TriggerConsumerHolder<>(c));
                sct.run();
            });
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
                publishSync(new Trigger<Void>(this, null, null, StateInt.States.INIT));
            else
                publish(new Trigger<Void>(this, null, null, StateInt.States.INIT));
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
