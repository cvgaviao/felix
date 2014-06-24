package org.apache.felix.dm.benchmark.scenario.impl;

import org.apache.felix.dm.benchmark.controller.ScenarioController;
import org.apache.felix.dm.benchmark.scenario.Track;

/**
 * One single music.
 */
public class TrackImpl implements Track {
    ScenarioController m_controller;

    void bindController(ScenarioController controller) {
        m_controller = controller;
    }

    void start() {
        m_controller.trackAdded(this);
    }
    
    void stop() {
        m_controller.trackRemoved(this);
    }

    @Override
    public void play() {
    }
}
