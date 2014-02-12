package org.labkey.api.laboratory;

import org.json.JSONObject;
import org.labkey.api.data.Container;
import org.labkey.api.data.TableInfo;
import org.labkey.api.ldk.AbstractNavItem;
import org.labkey.api.query.QueryAction;
import org.labkey.api.query.QueryService;
import org.labkey.api.query.UserSchema;
import org.labkey.api.security.User;
import org.labkey.api.view.ActionURL;

/**

 */
abstract public class AbstractQueryNavItem extends AbstractNavItem
{
    private String _name;
    private String _label;
    private String _category;
    private DataProvider _provider;
    private String _schema;
    private String _query;
    private boolean _visible = true;

    public AbstractQueryNavItem(DataProvider provider, String schema, String query, String category, String label)
    {
        _provider = provider;
        _schema = schema;
        _query = query;
        _category = category;
        _name = query;
        _label = label;
    }

    @Override
    public DataProvider getDataProvider()
    {
        return _provider;
    }

    @Override
    public String getName()
    {
        return _name;
    }

    @Override
    public String getLabel()
    {
        return _label;
    }

    @Override
    public String getCategory()
    {
        return _category;
    }

    @Override
    public String getRendererName()
    {
        return "linkWithLabel";
    }

    protected void setTargetContainer(Container c)
    {
        _targetContainer = c;
    }

    @Override
    public boolean getDefaultVisibility(Container c, User u)
    {
        return _visible;
    }

    public String getSchema()
    {
        return _schema;
    }

    public String getQuery()
    {
        return _query;
    }

    public void setVisible(boolean visible)
    {
        _visible = visible;
    }

    protected TableInfo getTableInfo(Container c, User u)
    {
        UserSchema us = QueryService.get().getUserSchema(u, getTargetContainer(c), _schema);
        if (us == null)
        {
            _log.error("Unable to find schema: " + _schema + " in container: " + getTargetContainer(c).getPath());
            return null;
        }

        return us.getTable(_query);
    }

    protected ActionURL getActionURL(Container c, User u)
    {
        return QueryService.get().urlFor(u, getTargetContainer(c), QueryAction.executeQuery, getSchema(), getQuery());
    }

    abstract protected String getItemText(Container c, User u);

    @Override
    public JSONObject toJSON(Container c, User u)
    {
        JSONObject json = super.toJSON(c, u);

        json.put("schemaName", _schema);
        json.put("queryName", _query);

        json.put("urlConfig", getUrlObject(getActionURL(c, u)));
        json.put("itemText", getItemText(c, u));

        return json;
    }
}
