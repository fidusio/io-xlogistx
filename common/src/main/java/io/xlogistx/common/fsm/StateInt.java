package io.xlogistx.common.fsm;

import org.zoxweb.shared.util.GetNVProperties;
import org.zoxweb.shared.util.GetName;
import org.zoxweb.shared.util.NVGenericMap;


public interface StateInt<P>
    extends GetName, GetNVProperties
{
    public enum States
        implements GetName
    {
        INIT("init"),
        FINAL("final"),
        ;

        private final String name;
        States(String name)
        {
            this.name = name;
        }
        @Override
        public String getName() {
            return name;
        }
    }


    TriggerConsumerInt<?>[] triggers();

    StateInt register(TriggerConsumerInt<?> tc);

    StateMachineInt getStateMachine();

    void setStateMachine(StateMachineInt smi);

    NVGenericMap getProperties();

}
