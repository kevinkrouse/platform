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
package org.labkey.api.reader;

import org.apache.poi.hssf.OldExcelFormatException;
import org.apache.poi.openxml4j.exceptions.InvalidFormatException;
import org.apache.poi.ss.format.CellFormat;
import org.apache.poi.ss.format.CellGeneralFormatter;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellStyle;
import org.apache.poi.ss.usermodel.DataFormat;
import org.apache.poi.ss.usermodel.DataFormatter;
import org.apache.poi.ss.usermodel.DateUtil;
import org.apache.poi.ss.usermodel.FormulaError;
import org.apache.poi.ss.usermodel.FormulaEvaluator;
import org.apache.poi.ss.usermodel.IndexedColors;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.ss.usermodel.WorkbookFactory;
import org.jetbrains.annotations.Nullable;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Test;
import org.labkey.api.data.ExcelWriter;
import org.labkey.api.reader.jxl.JxlWorkbook;
import org.labkey.api.settings.AppProps;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.text.DecimalFormat;
import java.text.Format;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Map;

/**
 * User: klum
 * Date: May 2, 2011
 * Time: 6:24:37 PM
 */
public class ExcelFactory
{
    public static final String SUB_TYPE_XSSF = "vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    public static final String SUB_TYPE_BIFF5 = "x-tika-msoffice";
    public static final String SUB_TYPE_BIFF8 = "vnd.ms-excel";

    public static Workbook create(File dataFile) throws IOException, InvalidFormatException
    {
        try
        {
            return WorkbookFactory.create(new FileInputStream(dataFile));
        }
        catch (OldExcelFormatException e)
        {
            return new JxlWorkbook(dataFile);
        }
        catch (IllegalArgumentException e)
        {
            throw new InvalidFormatException("Unable to open file as an Excel document. " + e.getMessage() == null ? "" : e.getMessage());
        }
/*
        DefaultDetector detector = new DefaultDetector();
        MediaType type = detector.detect(TikaInputStream.get(dataFile), new Metadata());

        if (SUB_TYPE_BIFF5.equals(type.getSubtype()))
            return new JxlWorkbook(dataFile);
        else
            return WorkbookFactory.create(new FileInputStream(dataFile));
*/
    }

    public static Workbook createFromArray(JSONArray sheetsArray, ExcelWriter.ExcelDocumentType docType) throws IOException
    {
        SimpleDateFormat dateFormat = new SimpleDateFormat(JSONObject.JAVASCRIPT_DATE_FORMAT);
        Workbook workbook = docType.createWorkbook();

        Map<String, CellStyle> customStyles = new HashMap<String, CellStyle>();

        for (int sheetIndex = 0; sheetIndex < sheetsArray.length(); sheetIndex++)
        {
            JSONObject sheetObject = sheetsArray.getJSONObject(sheetIndex);
            String sheetName = sheetObject.has("name") ? sheetObject.getString("name") : "Sheet" + sheetIndex;
            sheetName = ExcelWriter.cleanSheetName(sheetName);
            Sheet sheet = workbook.createSheet(sheetName);

            DataFormat dataFormat = workbook.createDataFormat();
            CellStyle defaultStyle = workbook.createCellStyle();
            CellStyle defaultDateStyle = workbook.createCellStyle();
            defaultDateStyle.setDataFormat(dataFormat.getFormat(org.labkey.api.util.DateUtil.getStandardDateFormatString()));

            CellStyle errorStyle = workbook.createCellStyle();
            errorStyle.setFillBackgroundColor(IndexedColors.RED.getIndex());

            JSONArray rowsArray = sheetObject.getJSONArray("data");
            for (int rowIndex = 0; rowIndex < rowsArray.length(); rowIndex++)
            {
                JSONArray rowArray = rowsArray.getJSONArray(rowIndex);

                Row row = sheet.createRow(rowIndex);

                for (int colIndex = 0; colIndex < rowArray.length(); colIndex++)
                {
                    Object value = rowArray.get(colIndex);
                    JSONObject metadataObject = null;
                    CellStyle cellStyle = defaultStyle;
                    if (value instanceof JSONObject)
                    {
                        metadataObject = (JSONObject)value;
                        value = metadataObject.get("value");
                    }

                    Cell cell = row.createCell(colIndex);
                    if (value instanceof java.lang.Number)
                    {
                        cell.setCellValue(((Number)value).doubleValue());
                        if (metadataObject != null && metadataObject.has("formatString"))
                        {
                            String formatString = metadataObject.getString("formatString");
                            cellStyle = getCustomCellStyle(workbook, customStyles, dataFormat, formatString);
                        }
                    }
                    else if (value instanceof Boolean)
                    {
                        cell.setCellValue(((Boolean) value).booleanValue());
                    }
                    else if (value instanceof String)
                    {
                        try
                        {
                            // JSON has no date literal syntax so try to parse all Strings as dates
                            Date d = dateFormat.parse((String)value);
                            try
                            {
                                if (metadataObject != null && metadataObject.has("formatString"))
                                {
                                    cellStyle = getCustomCellStyle(workbook, customStyles, dataFormat, metadataObject.getString("formatString"));
                                }
                                else
                                {
                                    cellStyle = defaultDateStyle;
                                }
                                boolean timeOnly = metadataObject != null && metadataObject.has("timeOnly") && Boolean.TRUE.equals(metadataObject.get("timeOnly"));
                                cell.setCellValue(d);
                            }
                            catch (IllegalArgumentException e)
                            {
                                // Invalid date format
                                cellStyle = errorStyle;
                                cell.setCellValue(e.getMessage());
                            }
                        }
                        catch (ParseException e)
                        {
                            // Not a date
                            cell.setCellValue((String)value);
                        }
                    }
                    else if (value != null)
                    {
                        cell.setCellValue(value.toString());
                    }
                    if (cell != null)
                    {
                        cell.setCellStyle(cellStyle);
                    }
                }
            }
        }

        return workbook;
    }

    private static CellStyle getCustomCellStyle(Workbook workbook, Map<String, CellStyle> customStyles, DataFormat dataFormat, String formatString)
    {
        CellStyle cellStyle;
        cellStyle = customStyles.get(formatString);
        if (cellStyle == null)
        {
            cellStyle = workbook.createCellStyle();
            cellStyle.setDataFormat(dataFormat.getFormat(formatString));
            customStyles.put(formatString, cellStyle);
        }
        return cellStyle;
    }

    /**
     * Helper to safely convert cell values to a string equivalent
     *
     */
    public static String getCellStringValue(Cell cell)
    {
        if (cell != null)
        {
            CellGeneralFormatter formatter = new CellGeneralFormatter();

            if ("General".equals(cell.getCellStyle().getDataFormatString()))
            {
                switch (cell.getCellType())
                {
                    case Cell.CELL_TYPE_BOOLEAN:
                        return formatter.format(cell.getBooleanCellValue());
                    case Cell.CELL_TYPE_NUMERIC:
                        return formatter.format(cell.getNumericCellValue());
                    case Cell.CELL_TYPE_FORMULA:
                    {
                        Workbook wb = cell.getSheet().getWorkbook();
                        FormulaEvaluator evaluator = createFormulaEvaluator(wb);
                        if (evaluator != null)
                        {
                            String val = evaluator.evaluate(cell).formatAsString();
                            return val;
                        }
                        return "";
                    }
                }
                return cell.getStringCellValue();
            }
            else if (isCellNumeric(cell) && DateUtil.isCellDateFormatted(cell) && cell.getDateCellValue() != null)
                return formatter.format(cell.getDateCellValue());
            else
                return CellFormat.getInstance(cell.getCellStyle().getDataFormatString()).apply(cell).text;
        }
        return "";
    }

    public static boolean isCellNumeric(Cell cell)
    {
        if (cell != null)
        {
            int type = cell.getCellType();

            return type == Cell.CELL_TYPE_BLANK || type == Cell.CELL_TYPE_NUMERIC || type == Cell.CELL_TYPE_FORMULA;
        }
        return false;
    }

    public static FormulaEvaluator createFormulaEvaluator(Workbook workbook)
    {
        return workbook != null ? workbook.getCreationHelper().createFormulaEvaluator() : null;
    }

    /**
     * Returns a specified cell given a col/row format
     */
    @Nullable
    public static Cell getCell(Sheet sheet, int colIdx, int rowIdx)
    {
        Row row = sheet.getRow(rowIdx);

        return row != null ? row.getCell(colIdx) : null;
    }

    /** Supports .xls (BIFF8 only), and .xlsx */
    public static JSONArray convertExcelToJSON(InputStream in, boolean extended) throws IOException, InvalidFormatException
    {
        return convertExcelToJSON(WorkbookFactory.create(in), extended);
    }

    /** Supports both new and old style .xls (BIFF5 and BIFF8), and .xlsx because we can reopen the stream if needed */
    public static JSONArray convertExcelToJSON(File excelFile, boolean extended) throws IOException, InvalidFormatException
    {
        return convertExcelToJSON(ExcelFactory.create(excelFile), extended);
    }

    /** Supports .xls (BIFF8 only) and .xlsx */
    public static JSONArray convertExcelToJSON(Workbook workbook, boolean extended) throws IOException
    {
        JSONArray result = new JSONArray();

        DataFormatter formatter = new DataFormatter();

        for (int sheetIndex = 0; sheetIndex < workbook.getNumberOfSheets(); sheetIndex++)
        {
            JSONArray rowsArray = new JSONArray();
            Sheet sheet = workbook.getSheetAt(sheetIndex);
            for (int rowIndex = 0; rowIndex <= sheet.getLastRowNum(); rowIndex++)
            {
                Row row = sheet.getRow(rowIndex);
                JSONArray rowArray = new JSONArray();
                if (row != null)
                {
                    for (int cellIndex = 0; cellIndex < row.getLastCellNum(); cellIndex++)
                    {
                        Object value;
                        JSONObject metadataMap = new JSONObject();
                        Cell cell = row.getCell(cellIndex, Row.CREATE_NULL_AS_BLANK);
                        String formatString = cell.getCellStyle().getDataFormatString();
                        String formattedValue;
                        if (cell.getCellComment() != null && cell.getCellComment().getString() != null)
                        {
                            metadataMap.put("comment", cell.getCellComment().getString().getString());
                        }

                        if ("General".equalsIgnoreCase(formatString))
                        {
                            formatString = null;
                        }

                        int effectiveCellType = cell.getCellType();
                        if (effectiveCellType == Cell.CELL_TYPE_FORMULA)
                        {
                            effectiveCellType = cell.getCachedFormulaResultType();
                            metadataMap.put("formula", cell.getCellFormula());
                        }

                        switch (effectiveCellType)
                        {
                            case Cell.CELL_TYPE_NUMERIC:
                                if (DateUtil.isCellDateFormatted(cell))
                                {
                                    value = cell.getDateCellValue();

                                    boolean timeOnly = false;
                                    Format format = formatter.createFormat(cell);
                                    if (format instanceof SimpleDateFormat)
                                    {
                                        formatString = ((SimpleDateFormat)format).toPattern();
                                        timeOnly = !formatString.contains("G") && !formatString.contains("y") &&
                                                !formatString.contains("M") && !formatString.contains("w") &&
                                                !formatString.contains("W") && !formatString.contains("D") &&
                                                !formatString.contains("d") && !formatString.contains("F") &&
                                                !formatString.contains("E");

                                        formattedValue = format.format(value);
                                    }
                                    else
                                    {
                                        formattedValue = formatter.formatCellValue(cell);
                                    }
                                    metadataMap.put("timeOnly", timeOnly);
                                }
                                else
                                {
                                    value = cell.getNumericCellValue();
                                    if (formatString != null)
                                    {
                                        // Excel escapes characters like $ in its number formats
                                        formatString = formatString.replace("\"", "");
                                        formattedValue = new DecimalFormat(formatString).format(value);
                                    }
                                    else
                                    {
                                        formattedValue = formatter.formatCellValue(cell);
                                    }
                                }
                                break;

                            case Cell.CELL_TYPE_BOOLEAN:
                                value = cell.getBooleanCellValue();
                                formattedValue = value == null ? null : value.toString();
                                break;

                            case Cell.CELL_TYPE_ERROR:
                                FormulaError error = FormulaError.forInt(cell.getErrorCellValue());
                                metadataMap.put("error", true);
                                if (error != null)
                                {
                                    value = error.getString();
                                }
                                else
                                {
                                    value = "Error! (code " + cell.getErrorCellValue() + ")";
                                }
                                formattedValue = value.toString();
                                break;

                            default:
                                value = cell.getStringCellValue();
                                if ("".equals(value))
                                {
                                    value = null;
                                }
                                formattedValue = cell.getStringCellValue();
                        }

                        if (extended)
                        {
                            metadataMap.put("value", value);
                            if (formatString != null && !"".equals(formatString))
                            {
                                metadataMap.put("formatString", formatString);
                            }
                            metadataMap.put("formattedValue", formattedValue);
                            rowArray.put(metadataMap);
                        }
                        else
                        {
                            rowArray.put(value);
                        }
                    }
                }
                rowsArray.put(rowArray);
            }
            JSONObject sheetJSON = new JSONObject();
            sheetJSON.put("name", workbook.getSheetName(sheetIndex));
            sheetJSON.put("data", rowsArray);
            result.put(sheetJSON);
        }
        return result;
    }

    public static String getCellContentsAt(Sheet sheet, int colIdx, int rowIdx)
    {
        return getCellStringValue(getCell(sheet, colIdx, rowIdx));
    }

    public static class ExcelFactoryTestCase extends Assert
    {
        @Test
        public void testCreateFromArray() throws IOException, InvalidFormatException
        {
            /* Initialize stream */
            ByteArrayOutputStream os = new ByteArrayOutputStream();

            String source = "{" +
                    "fileName: 'output.xls'," +
                    "sheets  : [" +
                        "{" +
                            "name : 'FirstSheet'," +
                            "data : [" +
                                "['Row1Col1', 'Row1Col2']," +
                                "['Row2Col1', 'Row2Col2']" +
                            "]" +
                        "},{" +
                            "name : 'SecondSheet'," +
                            "data : [" +
                                "['Col1Header', 'Col2Header']," +
                                "[{value: 1000.5, formatString: '0,000.00'}, {value: '5 Mar 2009 05:14:17', formatString: 'yyyy MMM dd'}]," +
                                "[{value: 2000.6, formatString: '0,000.00'}, {value: '6 Mar 2009 07:17:10', formatString: 'yyyy MMM dd'}]" +
                            "]" +
                        "}" +
                    "]" +
            "}";

            /* Initialize JSON - see LABKEY.Utils.convertToExcel */
            JSONObject root      = new JSONObject(source);
            JSONArray sheetArray = root.getJSONArray("sheets");

            Workbook wb = ExcelFactory.createFromArray(sheetArray, ExcelWriter.ExcelDocumentType.xls);
            wb.write(os);

            Sheet sheet = wb.getSheet("FirstSheet");
            assertNotNull(sheet);
            Cell cell = sheet.getRow(0).getCell(0);
            assertEquals("Row1Col1", cell.getStringCellValue());
            cell = sheet.getRow(1).getCell(1);
            assertEquals("Row2Col2", cell.getStringCellValue());

            // Validate equaility with '5 Mar 2009 05:14:17'
            sheet = wb.getSheet("SecondSheet");
            cell = sheet.getRow(1).getCell(1);
            Calendar cal = new GregorianCalendar();
            cal.setTime(cell.getDateCellValue());
            assertEquals(cal.get(Calendar.DATE), 5);
            assertEquals(cal.get(Calendar.MONTH), Calendar.MARCH);
            assertEquals(cal.get(Calendar.YEAR), 2009);
            assertEquals(cal.get(Calendar.HOUR), 5);
            assertEquals(cal.get(Calendar.MINUTE), 14);
            assertEquals(cal.get(Calendar.SECOND), 17);

            // Now make sure that it round-trips back to JSON correctly
            JSONArray array = convertExcelToJSON(wb, true);
            assertEquals(2, array.length());

            JSONObject sheet1JSON = array.getJSONObject(0);
            assertEquals("FirstSheet", sheet1JSON.getString("name"));
            JSONArray sheet1Values = sheet1JSON.getJSONArray("data");
            assertEquals("Wrong number of rows", 2, sheet1Values.length());
            assertEquals("Wrong number of columns", 2, sheet1Values.getJSONArray(0).length());
            assertEquals("Wrong number of columns", 2, sheet1Values.getJSONArray(1).length());
            assertEquals("Row1Col1", sheet1Values.getJSONArray(0).getJSONObject(0).getString("value"));
            assertEquals("Row1Col2", sheet1Values.getJSONArray(0).getJSONObject(1).getString("value"));
            assertEquals("Row2Col1", sheet1Values.getJSONArray(1).getJSONObject(0).getString("value"));
            assertEquals("Row2Col2", sheet1Values.getJSONArray(1).getJSONObject(1).getString("value"));

            JSONObject sheet2JSON = array.getJSONObject(1);
            assertEquals("SecondSheet", sheet2JSON.getString("name"));
            JSONArray sheet2Values = sheet2JSON.getJSONArray("data");
            assertEquals("Wrong number of rows", 3, sheet2Values.length());
            assertEquals("Wrong number of columns in row 0", 2, sheet2Values.getJSONArray(0).length());
            assertEquals("Wrong number of columns in row 1", 2, sheet2Values.getJSONArray(1).length());
            assertEquals("Wrong number of columns in row 2", 2, sheet2Values.getJSONArray(2).length());
            assertEquals("Col1Header", sheet2Values.getJSONArray(0).getJSONObject(0).getString("value"));
            assertEquals("Col2Header", sheet2Values.getJSONArray(0).getJSONObject(1).getString("value"));

            assertEquals(1000.5, sheet2Values.getJSONArray(1).getJSONObject(0).getDouble("value"));
            assertEquals("1,000.50", sheet2Values.getJSONArray(1).getJSONObject(0).getString("formattedValue"));
            assertEquals("0,000.00", sheet2Values.getJSONArray(1).getJSONObject(0).getString("formatString"));

            assertEquals(2000.6, sheet2Values.getJSONArray(2).getJSONObject(0).getDouble("value"));
            assertEquals("2,000.60", sheet2Values.getJSONArray(2).getJSONObject(0).getString("formattedValue"));
            assertEquals("0,000.00", sheet2Values.getJSONArray(2).getJSONObject(0).getString("formatString"));

//            assertEquals("Thu Mar 05 05:14:17 PST 2009", sheet2Values.getJSONArray(1).getJSONObject(1).getString("value"));
            assertEquals("2009 Mar 05", sheet2Values.getJSONArray(1).getJSONObject(1).getString("formattedValue"));
            assertEquals("yyyy MMM dd", sheet2Values.getJSONArray(1).getJSONObject(1).getString("formatString"));

//            assertEquals("Fri Mar 06 07:17:10 PST 2009", sheet2Values.getJSONArray(2).getJSONObject(1).getString("value"));
            assertEquals("2009 Mar 06", sheet2Values.getJSONArray(2).getJSONObject(1).getString("formattedValue"));
            assertEquals("yyyy MMM dd", sheet2Values.getJSONArray(2).getJSONObject(1).getString("formatString"));
        }

        @Test
        public void testParseXLS() throws Exception
        {
            validateSimpleExcel("SimpleExcelFile.xls");
        }

        @Test
        public void testParseXLSX() throws Exception
        {
            validateSimpleExcel("SimpleExcelFile.xlsx");
        }

        private void validateSimpleExcel(String filename) throws Exception
        {
            AppProps props = AppProps.getInstance();
            if (!props.isDevMode()) // We can only run the excel tests if we're in dev mode and have access to our samples
                return;

            String projectRootPath =  props.getProjectRoot();
            File projectRoot = new File(projectRootPath);
            File excelFile = new File(projectRoot, "sampledata/dataLoading/excel/" + filename);

            JSONArray jsonArray = ExcelFactory.convertExcelToJSON(excelFile, true);
            assertEquals("Wrong number of sheets", 3, jsonArray.length());
            JSONObject sheet1 = jsonArray.getJSONObject(0);
            assertEquals("Sheet name", "SheetA", sheet1.getString("name"));
            JSONArray sheet1Rows = sheet1.getJSONArray("data");
            assertEquals("Number of rows", 4, sheet1Rows.length());
            assertEquals("Number of columns - row 0", 2, sheet1Rows.getJSONArray(0).length());
            assertEquals("Number of columns - row 1", 2, sheet1Rows.getJSONArray(1).length());
            assertEquals("Number of columns - row 2", 2, sheet1Rows.getJSONArray(2).length());
            assertEquals("Number of columns - row 3", 2, sheet1Rows.getJSONArray(3).length());

            assertEquals("StringColumn", sheet1Rows.getJSONArray(0).getJSONObject(0).getString("value"));
            assertEquals("Hello", sheet1Rows.getJSONArray(1).getJSONObject(0).getString("value"));
            assertEquals("world", sheet1Rows.getJSONArray(2).getJSONObject(0).getString("value"));
            assertEquals(null, sheet1Rows.getJSONArray(3).getJSONObject(0).getString("value"));

            assertEquals("DateColumn", sheet1Rows.getJSONArray(0).getJSONObject(1).getString("value"));
            assertEquals("May 17, 2009", sheet1Rows.getJSONArray(1).getJSONObject(1).getString("formattedValue"));
            assertEquals("MMMM d, yyyy", sheet1Rows.getJSONArray(1).getJSONObject(1).getString("formatString"));
            assertEquals("12/21/08 7:31 PM", sheet1Rows.getJSONArray(2).getJSONObject(1).getString("formattedValue"));
            assertEquals("M/d/yy h:mm a", sheet1Rows.getJSONArray(2).getJSONObject(1).getString("formatString"));
            assertEquals("8:45 AM", sheet1Rows.getJSONArray(3).getJSONObject(1).getString("formattedValue"));
            assertEquals("h:mm a", sheet1Rows.getJSONArray(3).getJSONObject(1).getString("formatString"));
            
            JSONObject sheet2 = jsonArray.getJSONObject(1);
            assertEquals("Sheet name", "Other Sheet", sheet2.getString("name"));
            JSONArray sheet2Rows = sheet2.getJSONArray("data");
            assertEquals("Number of rows", 6, sheet2Rows.length());
            assertEquals("Number of columns - row 0", sheet2Rows.getJSONArray(0).length(), 1);

            assertEquals("NumberColumn", sheet2Rows.getJSONArray(0).getJSONObject(0).getString("value"));
            assertEquals(55.44, sheet2Rows.getJSONArray(1).getJSONObject(0).getDouble("value"));
            assertEquals("$55.44", sheet2Rows.getJSONArray(1).getJSONObject(0).getString("formattedValue"));
            assertEquals("$#,##0.00", sheet2Rows.getJSONArray(1).getJSONObject(0).getString("formatString"));
            assertEquals(100.34, sheet2Rows.getJSONArray(2).getJSONObject(0).getDouble("value"));
            assertEquals("100.34", sheet2Rows.getJSONArray(2).getJSONObject(0).getString("formattedValue"));
            assertEquals(-1.0, sheet2Rows.getJSONArray(3).getJSONObject(0).getDouble("value"));
            assertEquals("-1", sheet2Rows.getJSONArray(3).getJSONObject(0).getString("formattedValue"));
            assertEquals("61.00", sheet2Rows.getJSONArray(4).getJSONObject(0).getString("formattedValue"));
            assertEquals("56+5", sheet2Rows.getJSONArray(4).getJSONObject(0).getString("formula"));
            assertEquals("0.00", sheet2Rows.getJSONArray(4).getJSONObject(0).getString("formatString"));
            assertEquals("jeckels:\nA comment about the value 61\n", sheet2Rows.getJSONArray(4).getJSONObject(0).getString("comment"));
            assertEquals("#DIV/0!", sheet2Rows.getJSONArray(5).getJSONObject(0).getString("value"));
            assertTrue(sheet2Rows.getJSONArray(5).getJSONObject(0).getBoolean("error"));
        }
    }
}
