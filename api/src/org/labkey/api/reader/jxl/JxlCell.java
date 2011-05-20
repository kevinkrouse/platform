/*
 * Copyright (c) 2011 LabKey Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.labkey.api.reader.jxl;

import jxl.CellType;
import org.apache.poi.ss.formula.FormulaParseException;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellStyle;
import org.apache.poi.ss.usermodel.Comment;
import org.apache.poi.ss.usermodel.Hyperlink;
import org.apache.poi.ss.usermodel.RichTextString;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.util.CellRangeAddress;

import java.util.Calendar;
import java.util.Date;

/**
 * Created by IntelliJ IDEA.
 * User: klum
 * Date: May 2, 2011
 * Time: 6:54:03 PM
 */
public class JxlCell implements Cell
{
    private jxl.Cell _cell;
    private int _idx;
    private Row _row;

    public JxlCell(jxl.Cell cell, int idx, Row row)
    {
        _cell = cell;
        _idx = idx;
        _row = row;
    }

    @Override
    public int getColumnIndex()
    {
        return _idx;
    }

    @Override
    public int getRowIndex()
    {
        return _row.getRowNum();
    }

    @Override
    public Sheet getSheet()
    {
        return _row.getSheet();
    }

    @Override
    public Row getRow()
    {
        return _row;
    }

    @Override
    public void setCellType(int cellType)
    {
        throw new UnsupportedOperationException("method not yet supported");
    }

    @Override
    public int getCellType()
    {
        CellType type = _cell.getType();

        if (type.equals(CellType.EMPTY))
            return Cell.CELL_TYPE_BLANK;
        else if (type.equals(CellType.BOOLEAN))
            return Cell.CELL_TYPE_BOOLEAN;
        else if (type.equals(CellType.ERROR))
            return Cell.CELL_TYPE_ERROR;
        else if (type.equals(CellType.BOOLEAN_FORMULA) || type.equals(CellType.DATE_FORMULA) ||
                type.equals(CellType.NUMBER_FORMULA) || type.equals(CellType.STRING_FORMULA))
            return Cell.CELL_TYPE_FORMULA;
        else if (type.equals(CellType.NUMBER))
            return Cell.CELL_TYPE_NUMERIC;
        else if (type.equals(CellType.LABEL))
            return Cell.CELL_TYPE_STRING;

        return Cell.CELL_TYPE_STRING;
    }

    @Override
    public int getCachedFormulaResultType()
    {
        throw new UnsupportedOperationException("method not yet supported");
    }

    @Override
    public void setCellValue(double value)
    {
        throw new UnsupportedOperationException("method not yet supported");
    }

    @Override
    public void setCellValue(Date value)
    {
        throw new UnsupportedOperationException("method not yet supported");
    }

    @Override
    public void setCellValue(Calendar value)
    {
        throw new UnsupportedOperationException("method not yet supported");
    }

    @Override
    public void setCellValue(RichTextString value)
    {
        throw new UnsupportedOperationException("method not yet supported");
    }

    @Override
    public void setCellValue(String value)
    {
        throw new UnsupportedOperationException("method not yet supported");
    }

    @Override
    public void setCellFormula(String formula) throws FormulaParseException
    {
        throw new UnsupportedOperationException("method not yet supported");
    }

    @Override
    public String getCellFormula()
    {
        throw new UnsupportedOperationException("method not yet supported");
    }

    @Override
    public double getNumericCellValue()
    {
        return Double.parseDouble(_cell.getContents());
    }

    @Override
    public Date getDateCellValue()
    {
        return new Date(_cell.getContents());
    }

    @Override
    public RichTextString getRichStringCellValue()
    {
        throw new UnsupportedOperationException("method not yet supported");
    }

    @Override
    public String getStringCellValue()
    {
        return _cell.getContents();
    }

    @Override
    public void setCellValue(boolean value)
    {
        throw new UnsupportedOperationException("method not yet supported");
    }

    @Override
    public void setCellErrorValue(byte value)
    {
        throw new UnsupportedOperationException("method not yet supported");
    }

    @Override
    public boolean getBooleanCellValue()
    {
        return Boolean.parseBoolean(_cell.getContents());
    }

    @Override
    public byte getErrorCellValue()
    {
        throw new UnsupportedOperationException("method not yet supported");
    }

    @Override
    public void setCellStyle(CellStyle style)
    {
        throw new UnsupportedOperationException("method not yet supported");
    }

    @Override
    public CellStyle getCellStyle()
    {
        return new JxlCellStyle(_cell);
    }

    @Override
    public void setAsActiveCell()
    {
        throw new UnsupportedOperationException("method not yet supported");
    }

    @Override
    public void setCellComment(Comment comment)
    {
        throw new UnsupportedOperationException("method not yet supported");
    }

    @Override
    public Comment getCellComment()
    {
        throw new UnsupportedOperationException("method not yet supported");
    }

    @Override
    public void removeCellComment()
    {
        throw new UnsupportedOperationException("method not yet supported");
    }

    @Override
    public Hyperlink getHyperlink()
    {
        throw new UnsupportedOperationException("method not yet supported");
    }

    @Override
    public void setHyperlink(Hyperlink link)
    {
        throw new UnsupportedOperationException("method not yet supported");
    }

    @Override
    public CellRangeAddress getArrayFormulaRange()
    {
        throw new UnsupportedOperationException("method not yet supported");
    }

    @Override
    public boolean isPartOfArrayFormulaGroup()
    {
        throw new UnsupportedOperationException("method not yet supported");
    }
}
