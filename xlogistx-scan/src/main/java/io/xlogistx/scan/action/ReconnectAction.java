package io.xlogistx.scan.action;

import io.xlogistx.scan.model.ProbeState;
import io.xlogistx.scan.runtime.ProbeContext;

/**
 * reconnect — close the current channel and open a fresh one (to {@code port}, else the
 * target port) while the engine and accumulated result persist. This is how a probe uses
 * multiple connections. Fires {@code connected}, {@code error}, or {@code timeout}.
 */
public class ReconnectAction implements Action {

    @Override
    public String name() {
        return "reconnect";
    }

    @Override
    public void execute(ProbeContext context, ProbeState state) {
        context.reconnect(context.effectivePort(state.getPort()));
    }
}
