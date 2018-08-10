package org.labkey.api.reports;

import org.jetbrains.annotations.Nullable;
import org.labkey.api.data.Container;
import org.labkey.api.security.User;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineFactory;
import java.util.List;

public interface LabkeyScriptEngineManager
{
    ScriptEngine getEngineByName(String name);
    List<ScriptEngineFactory> getEngineFactories();

    /**
     * Return a script engine appropriate for the specified extension.
     */
    @Nullable
    ScriptEngine getEngineByExtension(Container c, String extension);

    /**
     * Return a script engine appropriate for the specified extension.
     * @param requestRemote R reports can pass a hint if they can run using a remote engine (Rserve). If there
     *                      is a remote engine available it will be returned over a local engine.
     */
    @Nullable
    ScriptEngine getEngineByExtension(Container c, String extension, boolean requestRemote);

    void deleteDefinition(User user, ExternalScriptEngineDefinition def);
    ExternalScriptEngineDefinition saveDefinition(User user, ExternalScriptEngineDefinition def);
    boolean isFactoryEnabled(ScriptEngineFactory factory);

    List<ExternalScriptEngineDefinition> getEngineDefinitions();
    List<ExternalScriptEngineDefinition> getEngineDefinitions(ExternalScriptEngineDefinition.Type type);
    ExternalScriptEngineDefinition getEngineDefinition(String name, ExternalScriptEngineDefinition.Type type);

    ExternalScriptEngineDefinition createEngineDefinition();
}
