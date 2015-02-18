package org.labkey.api.sequenceanalysis.pipeline;

import org.labkey.api.data.Container;
import org.labkey.api.module.Module;
import org.labkey.api.security.User;
import org.labkey.api.view.ActionURL;
import org.labkey.api.view.template.ClientDependency;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * Created by bimber on 2/10/2015.
 */
abstract public class AbstractParameterizedOutputHandler implements ParameterizedOutputHandler
{
    private Module _owner;
    private String _name;
    private String _description;
    private LinkedHashSet<String> _dependencies = new LinkedHashSet<>();
    private List<ToolParameterDescriptor> _parameters = new ArrayList<>();

    public AbstractParameterizedOutputHandler(Module owner, String name, String description, LinkedHashSet<String> dependencies, List<ToolParameterDescriptor> parameters)
    {
        _owner = owner;
        _name = name;
        _description = description;

        _dependencies.add("/sequenceanalysis/window/OutputHandlerWindow.js");
        if (dependencies != null)
            _dependencies.addAll(dependencies);
        if (parameters != null)
            _parameters.addAll(parameters);
    }

    @Override
    final public String getName()
    {
        return _name;
    }

    @Override
    final public String getDescription()
    {
        return _description;
    }

    @Override
    final public String getButtonJSHandler()
    {
        return "SequenceAnalysis.window.OutputHandlerWindow.buttonHandler";
    }

    @Override
    final public ActionURL getButtonSuccessUrl(Container c, User u, List<Integer> outputFileIds)
    {
        return null;
    }

    @Override
    final public Module getOwningModule()
    {
        return _owner;
    }

    @Override
    final public LinkedHashSet<ClientDependency> getClientDependencies()
    {
        LinkedHashSet<ClientDependency> ret = new LinkedHashSet<>();
        for (String path : _dependencies)
        {
            ret.add(ClientDependency.fromFilePath(path));
        }

        return ret;
    }

    @Override
    final public List<ToolParameterDescriptor> getParameters()
    {
        return _parameters;
    }
}
