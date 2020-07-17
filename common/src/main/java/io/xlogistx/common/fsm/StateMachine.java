package io.xlogistx.common.fsm;

import org.zoxweb.server.task.SupplierConsumerTask;
import org.zoxweb.server.task.TaskSchedulerProcessor;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.util.CanonicalID;
import org.zoxweb.shared.util.GetName;

import java.util.*;
import java.util.concurrent.Executor;
import java.util.logging.Logger;

public class StateMachine<C>
    implements StateMachineInt<C>
{

    private final static Logger log = Logger.getLogger(StateMachine.class.getName());
    private final String name;
    private final TaskSchedulerProcessor tsp;
    private Map<String, Set<TriggerConsumerInt<?>>> tcMap = new LinkedHashMap<String, Set<TriggerConsumerInt<?>>>();
    private Map<String, StateInt<?>> states = new LinkedHashMap<String, StateInt<?>>();
    private C config;
    private Executor executor;


    public StateMachine(String name)
    {
        this(name, TaskUtil.getDefaultTaskScheduler());
    }

    public StateMachine(String name, TaskSchedulerProcessor tsp)
    {
        this.name = name;
        this.tsp = tsp;
        executor = tsp.getExecutor();
    }

    @Override
    public StateMachineInt register(StateInt state) {
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
    public StateMachineInt publish(TriggerInt trigger) {
        Set<TriggerConsumerInt<?>> set = tcMap.get(trigger.getCanonicalID());
        if(set != null)
        {
            log.info("" + trigger);

            set.forEach(c -> executor.execute(new SupplierConsumerTask(trigger, new TriggerConsumerHolder<>(c))));
        }

        return this;
    }

    @Override
    public C getConfig() {
        return config;
    }

    @Override
    public StateMachineInt setConfig(C config) {
        this.config = config;
        return this;
    }

    @Override
    public String getName() {
        return name;
    }

    public void start()
    {
        if(tcMap.get(StateInt.States.INIT.getName()) != null)
            publish(new Trigger<Void>(this, null, null, StateInt.States.INIT.getName()));
        else
            throw new IllegalArgumentException("Not Init state");


    }


    public TaskSchedulerProcessor getScheduler(){
        return tsp;
    }

    @Override
    public Executor getExecutor() {
        return executor;
    }

    @Override
    public StateInt lookupState(String name) {
        return states.get(name);
    }

    @Override
    public StateInt lookupState(GetName name)
    {
        return lookupState(name.getName());
    }

    @Override
    public void close() {
    }


}
