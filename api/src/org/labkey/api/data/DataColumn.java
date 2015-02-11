/*
 * Copyright (c) 2004-2015 Fred Hutchinson Cancer Research Center
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.labkey.api.data;

import org.apache.commons.beanutils.ConvertUtils;
import org.apache.log4j.Logger;
import org.jetbrains.annotations.NotNull;
import org.labkey.api.action.SpringActionController;
import org.labkey.api.collections.NamedObject;
import org.labkey.api.collections.NamedObjectList;
import org.labkey.api.exp.property.IPropertyValidator;
import org.labkey.api.gwt.client.DefaultValueType;
import org.labkey.api.query.DetailsURL;
import org.labkey.api.query.FieldKey;
import org.labkey.api.query.QueryParseException;
import org.labkey.api.util.PageFlowUtil;
import org.labkey.api.util.StringExpression;
import org.labkey.api.util.StringExpressionFactory;
import org.labkey.api.util.StringUtilsLabKey;
import org.labkey.api.util.UniqueID;
import org.labkey.api.view.HttpView;

import java.io.IOException;
import java.io.Writer;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

public class DataColumn extends DisplayColumn
{
    private static final Logger LOG = Logger.getLogger(DataColumn.class);

    private ColumnInfo _boundColumn;
    private ColumnInfo _displayColumn;
    private List<ColumnInfo> _sortColumns;
    private ColumnInfo _filterColumn;

    private String _inputType;
    private int _inputRows;
    private int _inputLength;
    private boolean _preserveNewlines;
    private boolean _editable = true;

    //Careful, a renderer without a resultset is only good for input forms
    public DataColumn(ColumnInfo col)
    {
        this(col,true);
    }

    public DataColumn(ColumnInfo col, boolean withLookups)
    {
        _boundColumn = col;
        _displayColumn = getDisplayField(col, withLookups);
        _nowrap = _displayColumn.isNoWrap();
        _sortColumns = _displayColumn.getSortFields();
        _filterColumn = _displayColumn.getFilterField();

        _width = _displayColumn.getWidth();
        StringExpression url = _boundColumn.getEffectiveURL();
        if (null != url)
            super.setURLExpression(url);
        setLinkTarget(_boundColumn.getURLTargetWindow());
        setFormatString(_displayColumn.getFormat());
        setTsvFormatString(_displayColumn.getTsvFormatString());
        setExcelFormatString(_displayColumn.getExcelFormatString());
        setDescription(_boundColumn.getDescription());
        _inputType = _boundColumn.getInputType();
        try
        {
            if (null != _displayColumn && _boundColumn != _displayColumn && null != _boundColumn.getFk() && null != _boundColumn.getFkTableInfo())
            {
                if (_boundColumn.getFk() instanceof MultiValuedForeignKey)
                    _inputType = "select.multiple";
                else
                    _inputType = "select";
            }

        }
        catch (QueryParseException qpe)
        {
            /* fall through */
        }
        _inputRows = _boundColumn.getInputRows();
        // Assume that if the use can enter the value in a text area that they'll want to see
        // their newlines in grid views as well
        _preserveNewlines = _inputRows > 1;
        _inputLength = _boundColumn.getInputLength();
        _caption = StringExpressionFactory.create(_boundColumn.getLabel());
        _editable = !_boundColumn.isReadOnly() && _boundColumn.isUserEditable();
        _textAlign = _displayColumn.getTextAlign();
    }


    protected ColumnInfo getDisplayField(ColumnInfo col, boolean withLookups)
    {
        if (!withLookups)
            return col;
        ColumnInfo display = col.getDisplayField();
        return null==display ? col : display;
    }


    @Override
    public String toString()
    {
        return getClass().getName() + ": " + getName();
    }

    public int getInputRows()
    {
        return _inputRows;
    }

    public void setInputRows(int inputRows)
    {
        _inputRows = inputRows;
    }

    public int getInputLength()
    {
        return _inputLength;
    }

    public void setInputLength(int inputLength)
    {
        _inputLength = inputLength;
    }

    public boolean isPreserveNewlines()
    {
        return _preserveNewlines;
    }

    public void setPreserveNewlines(boolean preserveNewlines)
    {
        _preserveNewlines = preserveNewlines;
    }

    public ColumnInfo getColumnInfo()
    {
        return _boundColumn;
    }

    @Override
    public ColumnInfo getDisplayColumnInfo()
    {
        return _displayColumn;
    }

    public boolean isFilterable()
    {
        return _filterColumn != null;
    }

    public boolean isQueryColumn()
    {
        return true;
    }

    public void addQueryFieldKeys(Set<FieldKey> keys)
    {
        super.addQueryFieldKeys(keys);
        if (_boundColumn != null)
            keys.add(_boundColumn.getFieldKey());
        if (_displayColumn != null)
            keys.add(_displayColumn.getFieldKey());
        if (_filterColumn != null)
            keys.add(_filterColumn.getFieldKey());
        if (_sortColumns != null)
        {
            for (ColumnInfo col : _sortColumns)
                keys.add(col.getFieldKey());
        }
        StringExpression effectiveURL = _boundColumn.getEffectiveURL();
        if (effectiveURL instanceof DetailsURL)
        {
            keys.addAll(((DetailsURL) effectiveURL).getFieldKeys());
        }
    }

    public void addQueryColumns(Set<ColumnInfo> columns)
    {
        if (_boundColumn != null)
            columns.add(_boundColumn);
        if (_displayColumn != null)
            columns.add(_displayColumn);
        if (_filterColumn != null)
            columns.add(_filterColumn);
        if (_sortColumns != null)
            columns.addAll(_sortColumns);
    }

    public boolean isSortable()
    {
        return _sortColumns != null && _sortColumns.size() > 0;
    }

    public Object getValue(RenderContext ctx)
    {
        Object result = ctx.get(_boundColumn.getFieldKey());
        if (result == null)
        {
            // If we couldn't find it by FieldKey, check by alias as well
            result = _boundColumn.getValue(ctx);
        }
        return result;
    }

    public Object getDisplayValue(RenderContext ctx)
    {
        Object result = ctx.get(_displayColumn.getFieldKey());
        if (result == null)
        {
            // If we couldn't find it by FieldKey, check by alias as well
            result = _displayColumn.getValue(ctx);
        }
        return result;
    }

    public Object getJsonValue(RenderContext ctx)
    {
        return getValue(ctx);
    }

    public Class getValueClass()
    {
        return _boundColumn.getJavaClass();
    }

    public Class getDisplayValueClass()
    {
        return _displayColumn.getJavaClass();
    }

    public void renderDetailsCellContents(RenderContext ctx, Writer out) throws IOException
    {
        // By default, use the same rendering for both the details and grid views
        renderGridCellContents(ctx, out);
    }

    public void renderFilterOnClick(RenderContext ctx, Writer out) throws IOException
    {
        if (_filterColumn == null)
            return;

        String regionName = PageFlowUtil.jsString(ctx.getCurrentRegion().getName());
        String columnName = PageFlowUtil.jsString(_boundColumn.getFieldKey().toString());

        out.write("LABKEY.DataRegions[" + regionName + "]._openFilter(" + columnName + ");");
    }

    public String getClearFilter(RenderContext ctx)
    {
        if (_filterColumn == null)
            return "";
        String tableName = ctx.getCurrentRegion().getName();
        String fieldKey = _filterColumn.getFieldKey().toString();
        return "LABKEY.DataRegions[" + PageFlowUtil.jsString(tableName) + "]" +
                ".clearFilter(" + PageFlowUtil.jsString(fieldKey) + ")";
    }

    @Override
    public String getClearSortScript(RenderContext ctx)
    {
        String tableName = PageFlowUtil.jsString(ctx.getCurrentRegion().getName());
        String fieldKey = _displayColumn.getFieldKey().toString();
        return "LABKEY.DataRegions[" + tableName + "].clearSort(" + PageFlowUtil.jsString(fieldKey) + ");";
    }

    public void renderGridCellContents(RenderContext ctx, Writer out) throws IOException
    {
        Object o = getValue(ctx);

        if (null != o)
        {
            String url = renderURLorValueURL(ctx);

            if (null != url)
            {
                out.write("<a href=\"");
                out.write(PageFlowUtil.filter(url));

                String linkTitle = renderURLTitle(ctx);
                if (null != linkTitle)
                {
                    out.write("\" title=\"");
                    out.write(linkTitle);
                }

                String linkTarget = getLinkTarget();

                if (null != linkTarget)
                {
                    out.write("\" target=\"");
                    out.write(linkTarget);
                }

                String css = getCssStyle(ctx);
                if (!css.isEmpty())
                {
                    out.write("\" style=\"");
                    out.write(css);
                }
                
                out.write("\">");
            }

            out.write(getFormattedValue(ctx));

            if (null != url)
                out.write("</a>");
        }
        else
            out.write("&nbsp;");
    }

    protected String renderURLorValueURL(RenderContext ctx)
    {
        String url = renderURL(ctx);

        if (url == null)
        {
            // See if the value is itself a URL
            Object value = ctx.get(_displayColumn.getFieldKey());
            if (value != null)
            {
                String toString = value.toString();
                if (StringUtilsLabKey.startsWithURL(toString) &&
                        !toString.contains(" ") &&
                        !toString.contains("\n") &&
                        !toString.contains("\r") &&
                        !toString.contains("\t"))
                {
                    // Could do more sophisticated URL extraction to try to pull out, but this is likely
                    // to link most real URLs
                    url = toString;
                }
            }
        }
        return url;
    }
    
    @Override
    public String renderURL(RenderContext ctx)
    {
        Object displayValue = getDisplayValue(ctx);
        if (null == displayValue || "".equals(displayValue))
            return null;
        return super.renderURL(ctx);
    }

    protected String getHoverContent(RenderContext ctx)
    {
        ConditionalFormat format = findApplicableFormat(ctx);
        if (format == null)
        {
            return null;
        }
        StringBuilder sb = new StringBuilder("Formatting applied because ");
        String separator = "";
        for (SimpleFilter.FilterClause clause : format.getSimpleFilter().getClauses())
        {
            sb.append(separator);
            separator = " and ";
            clause.appendFilterText(sb, new SimpleFilter.ColumnNameFormatter());
        }
        sb.append(".");
        return sb.toString();
    }

    @Override
    protected String getHoverTitle(RenderContext ctx)
    {
        return "Formatting Details";
    }

    private ConditionalFormat findApplicableFormat(RenderContext ctx)
    {
        if (getBoundColumn() == null)
        {
            return null;
        }

        for (ConditionalFormat format : getBoundColumn().getConditionalFormats())
        {
            Object value = ctx.get(_displayColumn.getFieldKey());
            if (format.meetsCriteria(value))
            {
                return format;
            }
        }

        if (_displayColumn != getBoundColumn())
        {
            // If we're not showing the bound column, as in a lookup, check the display column to see if it has a
            // format preference
            for (ConditionalFormat format : _displayColumn.getConditionalFormats())
            {
                Object value = ctx.get(_displayColumn.getFieldKey());
                if (format.meetsCriteria(value))
                {
                    return format;
                }
            }
        }
        return null;
    }

    @Override @NotNull
    public String getCssStyle(RenderContext ctx)
    {
        String result = super.getCssStyle(ctx);
        ConditionalFormat format = findApplicableFormat(ctx);
        if (format != null)
        {
            result = result + ";" + format.getCssStyle();
        }
        return result;
    }

    @Override @NotNull
    public String getFormattedValue(RenderContext ctx)
    {
        StringBuilder sb = new StringBuilder();
        Object value = ctx.get(_displayColumn.getFieldKey());
        if (value == null)
        {
            // If we couldn't find it by FieldKey, check by alias as well
            value = _displayColumn.getValue(ctx);
        }
        if (value == null)
        {
            if (_displayColumn != _boundColumn)
            {
                Object boundValue = _boundColumn.getValue(ctx);
                // In many entry paths we've already checked for null, but not all (for example, MVDisplayColumn or when the TargetStudy no longer exists or is empty string)
                if (boundValue == null || "".equals(boundValue))
                {
                    sb.append("&nbsp;");
                }
                else
                {
                    sb.append(PageFlowUtil.filter("<" + boundValue + ">"));
                }
            }
        }
        else
        {
            String formatted;
            if (null != _format)
            {
                try
                {
                    formatted = _format.format(value);
                }
                catch (IllegalArgumentException e)
                {
                    LOG.warn("Unable to apply format, likely a SQL type mismatch between XML metadata and actual ResultSet");
                    formatted = ConvertUtils.convert(value);
                }
            }
            else if (isHtmlFiltered())
                formatted = PageFlowUtil.filter(ConvertUtils.convert(value));
            else
                formatted = ConvertUtils.convert(value);

            if (formatted.length() == 0)
                formatted = "&nbsp;";
            else if (_preserveNewlines)
                formatted = formatted.replaceAll("\\n", "<br>\n");
            else if (value instanceof Date)
                formatted = "<nobr>" + formatted + "</nobr>";

            sb.append(formatted);
        }

        return sb.toString();
    }

    protected boolean isDisabledInput()
    {
        return _boundColumn.getDefaultValueType() == DefaultValueType.FIXED_NON_EDITABLE ||
                _boundColumn.isReadOnly() || !_boundColumn.isUserEditable();
    }

    protected boolean isSelectInputSelected(String entryName, Object value, String valueStr)
    {
        if (value instanceof Collection)
        {
            // CONSIDER: stringify values in collection?
            return ((Collection)value).contains(entryName);
        }
        return null != valueStr && entryName.equals(valueStr);
    }

    protected String getSelectInputDisplayValue(NamedObject entry)
    {
        return entry.getObject().toString();
    }

    public void renderInputHtml(RenderContext ctx, Writer out, Object value) throws IOException
    {
        boolean disabledInput = isDisabledInput();
        String formFieldName = getFormFieldName(ctx);

        String strVal = "";
        //UNDONE: Should use output format here.
        if (null != value)
        {
            // 4934: Don't render form input values with formatter since we don't parse formatted inputs on post.
            // For now, we can at least render disabled inputs with formatting since a
            // hidden input with the actual value is emitted for diabled items.
            if (null != _format && disabledInput)
                try
                {
                    strVal = _format.format(value);
                }
                catch (IllegalArgumentException x)
                {
                    strVal = ConvertUtils.convert(value);
                }
            else
                strVal = ConvertUtils.convert(value);
        }

        if (_boundColumn.isVersionColumn())
        {
            //should be in hidden field.
        }
        else if (_boundColumn.isAutoIncrement())
        {
            renderHiddenFormInput(ctx, out, formFieldName, value);
            if (null != value)
            {
                out.write(PageFlowUtil.filter(strVal));
            }
        }
        else if (_inputType.toLowerCase().startsWith("select"))
        {
            NamedObjectList entryList = _boundColumn.getFk().getSelectList(ctx);
            NamedObject[] entries = entryList.toArray();
            String valueStr = ConvertUtils.convert(value);

            out.write("<select");
            outputName(ctx, out, formFieldName);
            if (disabledInput)
                out.write(" DISABLED");
            if (_inputType.equalsIgnoreCase("select.multiple"))
                out.write(" multiple");
            out.write(">\n");
            out.write("<option value=\"\"></option>");
            for (NamedObject entry : entries)
            {
                String entryName = entry.getName();
                out.write("  <option value=\"");
                out.write(PageFlowUtil.filter(entryName));
                out.write("\"");
                if (isSelectInputSelected(entryName, value, valueStr))
                    out.write(" selected");
                out.write(">");
                if (null != entry.getObject())
                    out.write(PageFlowUtil.filter(getSelectInputDisplayValue(entry)));
                out.write("</option>\n");
            }
            out.write("</select>");
            // disabled inputs are not posted with the form, so we output a hidden form element:
            if (disabledInput)
                renderHiddenFormInput(ctx, out, formFieldName, value);
        }
        else if (_inputType.equalsIgnoreCase("textarea"))
        {
            out.write("<textarea cols='");
            out.write(String.valueOf(_inputLength));
            out.write("' rows='");
            out.write(String.valueOf(_inputRows));
            out.write("'");
            outputName(ctx, out, formFieldName);
            if (disabledInput)
                out.write(" DISABLED");
            out.write(">");
            out.write(PageFlowUtil.filter(strVal));
            out.write("</textarea>\n");
            // disabled inputs are not posted with the form, so we output a hidden form element:
            if (disabledInput)
                renderHiddenFormInput(ctx, out, formFieldName, value);
        }
        else if (_inputType.equalsIgnoreCase("file"))
        {
            out.write("<input");
            outputName(ctx, out, formFieldName);
            if (disabledInput)
                out.write(" DISABLED");
            out.write(" type='file'>\n");
        }
        else if (_inputType.equalsIgnoreCase("checkbox"))
        {
            boolean checked = ColumnInfo.booleanFromObj(ConvertUtils.convert(value));
            out.write("<input type='checkbox'");
            if (checked)
                out.write(" CHECKED");
            if (disabledInput)
                out.write(" DISABLED");
            outputName(ctx, out, formFieldName);
            out.write(" value='1'>");
            /*
             * Checkboxes are weird. If set to FALSE they don't post at all, so it's impossible to tell
             * the difference between values that weren't on the html form at all and ones that were set
             * to false by the user.
             *
             * To fix this, each checkbox posts a hidden field named @columnName.  Spring parameter
             * binding uses these special fields to set all unposted checkbox values to false.
             */
            out.write("<input type=\"hidden\" name=\"");
            out.write(SpringActionController.FIELD_MARKER);
            out.write(PageFlowUtil.filter(formFieldName));
            out.write("\" value=\"1\">");
            // disabled inputs are not posted with the form, so we output a hidden form element:
            if (disabledInput)
                renderHiddenFormInput(ctx, out, formFieldName, checked ? "1" : "");
        }
        else if (_inputType.equalsIgnoreCase("none"))
            ; //do nothing. Used 
        else
        {
            if (getAutoCompleteURLPrefix() != null)
            {
                String renderId = "auto-complete-div-" + UniqueID.getRequestScopedUID(HttpView.currentRequest());
                StringBuilder sb = new StringBuilder();

                sb.append("<script type=\"text/javascript\">");
                sb.append("Ext4.onReady(function(){\n" +
                    "        Ext4.create('LABKEY.element.AutoCompletionField', {\n" +
                    "            renderTo        : " + PageFlowUtil.jsString(renderId) + ",\n" +
                    "            completionUrl   : " + PageFlowUtil.jsString(getAutoCompleteURLPrefix()) + ",\n" +
                    "            sharedStore     : true,\n" +
                    "            sharedStoreId   : " + PageFlowUtil.jsString(getAutoCompleteURLPrefix()) + ",\n" +
                    "            tagConfig   : {\n" +
                    "                tag     : 'input',\n" +
                    "                type    : 'text',\n" +
                    "                name    : " + PageFlowUtil.jsString(formFieldName) + ",\n" +
                    "                size    : " + _inputLength + ",\n" +
                    "                value   : " + PageFlowUtil.jsString(strVal) + ",\n" +
                    "                autocomplete : 'off'\n" +
                    "            }\n" +
                    "        });\n" +
                    "      });\n");
                sb.append("</script>\n");
                sb.append("<div id='").append(renderId).append("'></div>");
                out.write(sb.toString());
            }
            else
            {
                out.write("<input type='text' size='");
                out.write(Integer.toString(_inputLength));
                out.write("'");
                outputName(ctx, out, formFieldName);
                if (disabledInput)
                    out.write(" DISABLED");
                out.write(" value=\"");
                out.write(PageFlowUtil.filter(strVal));
                out.write("\"");
                out.write(">");
                // disabled inputs are not posted with the form, so we output a hidden form element:
                if (disabledInput)
                    renderHiddenFormInput(ctx, out, formFieldName, value);
            }
        }
    }

    protected String getAutoCompleteURLPrefix()
    {
        return null;
    }

    /**
     * put quotes around a JavaScript string, and HTML encode that.
     */
    protected String hq(Object value)
    {
        return PageFlowUtil.filterQuote(value);
    }

    protected String h(Object value)
    {
        return PageFlowUtil.filter(value);
    }

    public void renderSortHandler(RenderContext ctx, Writer out, Sort.SortDirection sort) throws IOException
    {
        if (_sortColumns == null || _sortColumns.size() == 0)
        {
            return;
        }
        String uri;
        String regionName = ctx.getCurrentRegion().getName();
        String fieldKey = _displayColumn.getFieldKey().toString();
        uri = "doSort("+ PageFlowUtil.jsString(regionName) + "," + PageFlowUtil.jsString(fieldKey) + ",'" + h(sort.getDir()) + "')";
        out.write(uri);
    }

    public void renderTitle(RenderContext ctx, Writer out) throws IOException
    {
        String title = PageFlowUtil.filter(_caption.eval(ctx));
        if (title.length() == 0)
        {
            title = "&nbsp;";
        }
        out.write(title);
    }

    public void renderDetailsCaptionCell(RenderContext ctx, Writer out) throws IOException
    {
        if (null == _caption)
            return;

        out.write("<td class='labkey-form-label'>");
        renderTitle(ctx, out);
        int mode = ctx.getMode();
        if ((mode == DataRegion.MODE_INSERT || mode == DataRegion.MODE_UPDATE) && isEditable())
        {
            if (_boundColumn != null)
            {
                StringBuilder sb = new StringBuilder();
                if (_boundColumn.getFriendlyTypeName() != null && !_inputType.toLowerCase().startsWith("select"))
                {
                    sb.append("Type: ").append(_boundColumn.getFriendlyTypeName()).append("\n");
                }
                if (_boundColumn.getDescription() != null)
                {
                    sb.append("Description: ").append(_boundColumn.getDescription()).append("\n");
                }
                for (IPropertyValidator validator : _boundColumn.getValidators())
                    sb.append("Validator: ").append(validator).append("\n");
                if (renderRequiredIndicators() && _boundColumn.isRequired() && !_boundColumn.isBooleanType())
                {
                    out.write(" *");
                    sb.append("This field is required.\n");
                }
                if (sb.length() > 0)
                {
                    out.write(PageFlowUtil.helpPopup(_boundColumn.getLabel(), sb.toString()));
                }
            }
        }
        out.write("</td>");
    }

    protected boolean renderRequiredIndicators()
    {
        return true;
    }

    public boolean isEditable()
    {
        return _editable;
    }

    public void setEditable(boolean b)
    {
        _editable = b;
    }

    public void render(RenderContext ctx, Writer out) throws IOException
    {
        if (ctx.getMode() == DataRegion.MODE_INSERT || ctx.getMode() == DataRegion.MODE_UPDATE)
            renderInputHtml(ctx, out, getInputValue(ctx));
        else
            renderDetailsCellContents(ctx, out);
    }

    public String getInputType()
    {
        return _inputType;
    }

    public void setInputType(String _inputType)
    {
        this._inputType = _inputType;
    }

    public void setBoundColumn(ColumnInfo column)
    {
        _boundColumn = column;
    }

    public ColumnInfo getBoundColumn()
    {
        return _boundColumn;
    }

    public void setDisplayColumn(ColumnInfo column)
    {
        _displayColumn = column;
    }

    public ColumnInfo getDisplayColumn()
    {
        return _displayColumn;
    }
}
