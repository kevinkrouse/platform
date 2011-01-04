/*
 * Copyright (c) 2008-2010 LabKey Corporation
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

import org.jetbrains.annotations.NotNull;
import org.labkey.api.query.FieldKey;
import org.labkey.api.security.permissions.Permission;
import org.labkey.api.security.roles.Role;
import org.labkey.api.util.StringExpression;
import org.labkey.api.view.ViewContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;
import java.sql.SQLException;
import java.text.Format;
import java.util.Map;
import java.util.Set;

/**
 * User: kevink
 * Date: Nov 20, 2008 4:25:54 PM
 */
public class DisplayColumnDecorator extends DisplayColumn
{
    protected DisplayColumn _column;

    public DisplayColumnDecorator(DisplayColumn column)
    {
        _column = column;
    }

    @Override
    public void renderGridCellContents(RenderContext ctx, Writer out) throws IOException
    {
        _column.renderGridCellContents(ctx, out);
    }

    @Override
    public void renderDetailsCellContents(RenderContext ctx, Writer out) throws IOException
    {
        _column.renderDetailsCellContents(ctx, out);
    }

    @Override
    public void renderTitle(RenderContext ctx, Writer out) throws IOException
    {
        _column.renderTitle(ctx, out);
    }

    @Override
    public void renderGridEnd(RenderContext ctx, Writer out) throws IOException
    {
        _column.renderGridEnd(ctx, out);
    }

    @Override
    public boolean isSortable()
    {
        return _column.isSortable();
    }

    @Override
    public boolean isFilterable()
    {
        return _column.isFilterable();
    }

    @Override
    public boolean isEditable()
    {
        return _column.isEditable();
    }

    @Override
    public void renderSortHandler(RenderContext ctx, Writer out, Sort.SortDirection sort) throws IOException
    {
        _column.renderSortHandler(ctx, out, sort);
    }

    @Override
    public void renderFilterOnClick(RenderContext ctx, Writer out) throws IOException
    {
        _column.renderFilterOnClick(ctx, out);
    }

    @Override
    public void renderInputHtml(RenderContext ctx, Writer out, Object value) throws IOException
    {
        _column.renderInputHtml(ctx, out, value);
    }

    @Override
    public String renderURL(RenderContext ctx)
    {
        return _column.renderURL(ctx);
    }

    @Override
    public String getURL()
    {
        return _column.getURL();
    }

    @Override
    public void setURL(String url)
    {
        _column.setURL(url);
    }

    @Override
    public void setURLExpression(StringExpression se)
    {
        _column.setURLExpression(se);
    }

    @Override
    public StringExpression getURLExpression()
    {
        return _column.getURLExpression();
    }

    @Override
    public StringExpression compileExpression(ViewContext context)
    {
        return _column.compileExpression(context);
    }

    @Override
    public boolean isQueryColumn()
    {
        return _column.isQueryColumn();
    }

    @Override
    public void addQueryFieldKeys(Set<FieldKey> keys)
    {
        _column.addQueryFieldKeys(keys);
    }

    @Override
    public void addQueryColumns(Set<ColumnInfo> columns)
    {
        _column.addQueryColumns(columns);
    }

    @Override
    public ColumnInfo getColumnInfo()
    {
        return _column.getColumnInfo();
    }

    @Override
    public Object getValue(RenderContext ctx)
    {
        return _column.getValue(ctx);
    }

    @Override
    public Class getValueClass()
    {
        return _column.getValueClass();
    }

    @Override
    public Object getJsonValue(RenderContext ctx)
    {
        return _column.getJsonValue(ctx);
    }

    @Override
    public String getName()
    {
        return _column.getName();
    }

    @Override
    protected String getInputPrefix()
    {
        return _column.getInputPrefix();
    }

    @Override
    protected void setInputPrefix(String inputPrefix)
    {
        _column.setInputPrefix(inputPrefix);
    }

    @Override
    public void setWidth(String width)
    {
        _column.setWidth(width);
    }

    @Override
    public String getWidth()
    {
        return _column.getWidth();
    }

    @Override
    public void setNoWrap(boolean nowrap)
    {
        _column.setNoWrap(nowrap);
    }

    @Override
    public void setFormatString(String formatString)
    {
        _column.setFormatString(formatString);
    }

    @Override
    public void setTsvFormatString(String formatString)
    {
        _column.setTsvFormatString(formatString);
    }

    @Override
    public Format getFormat()
    {
        return _column.getFormat();
    }

    @Override
    public Format getTsvFormat()
    {
        return _column.getTsvFormat();
    }

    @Override
    public String getFormattedValue(RenderContext ctx)
    {
        return _column.getFormattedValue(ctx);
    }

    @Override
    public String getTsvFormattedValue(RenderContext ctx)
    {
        return _column.getTsvFormattedValue(ctx);
    }

    @Override
    public String getDisplayJsonTypeName()
    {
        return _column.getDisplayJsonTypeName();
    }

    @Override
    public String getJsonTypeName()
    {
        return _column.getJsonTypeName();
    }

    @Override
    public Object getDisplayValue(RenderContext ctx)
    {
        return _column.getDisplayValue(ctx);
    }

    @Override
    public Class getDisplayValueClass()
    {
        return _column.getDisplayValueClass();
    }

    @Override
    public void setTextAlign(String textAlign)
    {
        _column.setTextAlign(textAlign);
    }

    @Override
    public String getTextAlign()
    {
        return _column.getTextAlign();
    }

    @Override
    public void setGridHeaderClass(String headerClass)
    {
        _column.setGridHeaderClass(headerClass);
    }

    @Override
    public void addGridHeaderClass(String headerClass)
    {
        _column.addGridHeaderClass(headerClass);
    }

    @Override
    public String getGridHeaderClass()
    {
        return _column.getGridHeaderClass();
    }

    @Override
    public void renderColTag(Writer out, boolean isLast) throws IOException
    {
        _column.renderColTag(out, isLast);
    }

    @Override
    public String getGridHeaderCell(RenderContext ctx)
    {
        return _column.getGridHeaderCell(ctx);
    }

    @Override
    public String getDefaultHeaderStyle()
    {
        return _column.getDefaultHeaderStyle();
    }

    @Override
    public void renderGridHeaderCell(RenderContext ctx, Writer out) throws IOException, SQLException
    {
        _column.renderGridHeaderCell(ctx, out);
    }

    @Override
    public void renderGridHeaderCell(RenderContext ctx, Writer out, String headerClass) throws IOException, SQLException
    {
        _column.renderGridHeaderCell(ctx, out, headerClass);
    }

    @Override
    public boolean isUserSort(RenderContext ctx)
    {
        return _column.isUserSort(ctx);
    }

    @Override
    public String getGridDataCell(RenderContext ctx)
    {
        return _column.getGridDataCell(ctx);
    }

    @NotNull
    @Override
    protected String getCssStyle(RenderContext ctx)
    {
        return _column.getCssStyle(ctx);
    }

    @Override
    public String getCaption()
    {
        return _column.getCaption();
    }

    @Override
    public String getCaption(RenderContext ctx)
    {
        return _column.getCaption(ctx);
    }

    @Override
    public String getCaption(RenderContext ctx, boolean htmlEncode)
    {
        return _column.getCaption(ctx, htmlEncode);
    }

    @Override
    public String getDetailsCaptionCell(RenderContext ctx)
    {
        return _column.getDetailsCaptionCell(ctx);
    }

    @Override
    public void renderDetailsCaptionCell(RenderContext ctx, Writer out) throws IOException
    {
        _column.renderDetailsCaptionCell(ctx, out);
    }

    @Override
    public String getDetailsData(RenderContext ctx)
    {
        return _column.getDetailsData(ctx);
    }

    @Override
    public void renderDetailsData(RenderContext ctx, Writer out, int span) throws IOException
    {
        _column.renderDetailsData(ctx, out, span);
    }

    @Override
    public String getInputCell(RenderContext ctx)
    {
        return _column.getInputCell(ctx);
    }

    @Override
    protected Object getInputValue(RenderContext ctx)
    {
        return _column.getInputValue(ctx);
    }

    @Override
    public String getFormFieldName(RenderContext ctx)
    {
        return _column.getFormFieldName(ctx);
    }

    @Override
    protected void outputName(RenderContext ctx, Writer out, String formFieldName) throws IOException
    {
        _column.outputName(ctx, out, formFieldName);
    }

    @Override
    public void renderHiddenFormInput(RenderContext ctx, Writer out) throws IOException
    {
        _column.renderHiddenFormInput(ctx, out);
    }

    @Override
    protected void renderHiddenFormInput(RenderContext ctx, Writer out, String formFieldName, Object value) throws IOException
    {
        _column.renderHiddenFormInput(ctx, out, formFieldName, value);
    }

    @Override
    public void renderInputCell(RenderContext ctx, Writer out, int span) throws IOException
    {
        _column.renderInputCell(ctx, out, span);
    }

    @Override
    public String getSortHandler(RenderContext ctx, Sort.SortDirection sort)
    {
        return _column.getSortHandler(ctx, sort);
    }

    @Override
    public String getFilterOnClick(RenderContext ctx)
    {
        return _column.getFilterOnClick(ctx);
    }

    @Override
    public String getClearFilter(RenderContext ctx)
    {
        return _column.getClearFilter(ctx);
    }

    @Override
    public String getClearSortScript(RenderContext ctx)
    {
        return _column.getClearSortScript(ctx);
    }

    @Override
    public String getInputHtml(RenderContext ctx)
    {
        return _column.getInputHtml(ctx);
    }

    @Override
    public boolean isHtmlFiltered()
    {
        return _column.isHtmlFiltered();
    }

    @Override
    public void setHtmlFiltered(boolean htmlFiltered)
    {
        _column.setHtmlFiltered(htmlFiltered);
    }

    @Override
    public void setLinkTarget(String linkTarget)
    {
        _column.setLinkTarget(linkTarget);
    }

    @Override
    public String getLinkTarget()
    {
        return _column.getLinkTarget();
    }

    @Override
    public String getExcelFormatString()
    {
        return _column.getExcelFormatString();
    }

    @Override
    public void setExcelFormatString(String excelFormatString)
    {
        _column.setExcelFormatString(excelFormatString);
    }

    @Override
    public String getDescription()
    {
        return _column.getDescription();
    }

    @Override
    public void setDescription(String _description)
    {
        _column.setDescription(_description);
    }

    @Override
    public void addDisplayClass(String className)
    {
        _column.addDisplayClass(className);
    }

    @Override
    public String getFormatString()
    {
        return _column.getFormatString();
    }

    @Override
    public void setName(String name)
    {
        _column.setName(name);
    }

    @Override
    public String getTsvFormatString()
    {
        return _column.getTsvFormatString();
    }

    @Override
    public String getContentType()
    {
        return _column.getContentType();
    }

    @Override
    public Class<? extends Permission> getDisplayPermission()
    {
        return _column.getDisplayPermission();
    }

    @Override
    public void setDisplayPermission(Class<? extends Permission> perm)
    {
        _column.setDisplayPermission(perm);
    }

    @Override
    public void addContextualRole(Class<? extends Role> role)
    {
        _column.addContextualRole(role);
    }

    @Override
    public boolean isVisible(RenderContext ctx)
    {
        return _column.isVisible(ctx);
    }

    @Override
    public void setVisible(boolean visible)
    {
        _column.setVisible(visible);
    }

    @Override
    public boolean shouldRender(RenderContext ctx)
    {
        return _column.shouldRender(ctx);
    }

    @Override
    public String getOutput(RenderContext ctx)
    {
        return _column.getOutput(ctx);
    }

    @Override
    public void setCaption(String caption)
    {
        _column.setCaption(caption);
    }

    @Override
    public String getCaptionExpr()
    {
        return _column.getCaptionExpr();
    }

    @Override
    public int getDisplayModes()
    {
        return _column.getDisplayModes();
    }

    @Override
    public void setDisplayModes(int displayModes)
    {
        _column.setDisplayModes(displayModes);
    }

    @Override
    public void render(RenderContext ctx, HttpServletRequest request, HttpServletResponse response) throws IOException
    {
        _column.render(ctx, request, response);
    }

    @Override
    public void renderView(Map model, Writer out) throws IOException
    {
        _column.renderView(model, out);
    }

    @Override
    public void render(RenderContext ctx, Writer out) throws IOException
    {
        _column.render(ctx, out);
    }

    @Override
    public void lock()
    {
        _column.lock();
    }

    @Override
    public void checkLocked()
    {
        _column.checkLocked();
    }
}
