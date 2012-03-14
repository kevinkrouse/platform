package org.labkey.study.query;

import org.apache.commons.lang3.math.NumberUtils;
import org.labkey.api.data.ColumnInfo;
import org.labkey.api.query.AliasedColumn;
import org.labkey.api.query.FieldKey;
import org.labkey.api.query.FilteredTable;
import org.labkey.api.study.StudyService;
import org.labkey.study.SampleManager;
import org.labkey.study.model.PrimaryType;
import org.labkey.study.model.SpecimenTypeSummary;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * User: klum
 * Date: Mar 5, 2012
 */
public class SpecimenPivotByPrimaryType extends BaseSpecimenPivotTable
{
    public static final String PIVOT_BY_PRIMARY_TYPE = "Primary Type Vial Counts";

    public SpecimenPivotByPrimaryType(final StudyQuerySchema schema)
    {
        super(SpecimenReportQuery.getPivotByPrimaryType(schema.getContainer(), schema.getUser()), schema);
        setDescription("Contains up to one row of Specimen Primary Type totals for each " + StudyService.get().getSubjectNounSingular(getContainer()) +
            "/visit combination.");

        try {
            Map<Integer, String> primaryTypeMap = getPrimaryTypeMap(getContainer());
            Map<Integer, String> allPrimaryTypes = new HashMap<Integer, String>();
            
            for (PrimaryType type : SampleManager.getInstance().getPrimaryTypes(getContainer()))
                allPrimaryTypes.put(Long.valueOf(type.getRowId()).intValue(), type.getPrimaryType());

            for (ColumnInfo col : getRealTable().getColumns())
            {
                // look for the primary/derivative pivot encoding
                String parts[] = col.getName().split(AGGREGATE_DELIM);

                if (parts != null && parts.length == 2)
                {
                    int primaryId = NumberUtils.toInt(parts[0]);

                    if (primaryTypeMap.containsKey(primaryId))
                    {
                        wrapPivotColumn(col, primaryTypeMap.get(primaryId), parts[1]);
                    }
                    else if (allPrimaryTypes.containsKey(primaryId))
                    {
                        ColumnInfo wrappedCol = wrapPivotColumn(col, allPrimaryTypes.get(primaryId), parts[1]);

                        wrappedCol.setHidden(true);
                    }
                }
            }

            setDefaultVisibleColumns(getDefaultVisibleColumns());

            addWrapColumn(_rootTable.getColumn("Container"));
        }
        catch (SQLException e)
        {
            throw new RuntimeException(e);
        }
    }

    private List<FieldKey> getDefaultColumns(StudyQuerySchema schema)
    {
        List<FieldKey> defaultColumns = new ArrayList<FieldKey>();

        defaultColumns.add(FieldKey.fromParts(StudyService.get().getSubjectColumnName(getContainer())));
        defaultColumns.add(FieldKey.fromParts("Visit"));

        SpecimenTypeSummary summary = SampleManager.getInstance().getSpecimenTypeSummary(getContainer());
        Map<String, String> nonZeroPrimaryTypes = new HashMap<String, String>();

        for (SpecimenTypeSummary.TypeCount typeCount : summary.getPrimaryTypes())
            nonZeroPrimaryTypes.put(typeCount.getLabel(), typeCount.getLabel());

        for (ColumnInfo col : getColumns())
        {
            String[] parts = col.getName().split("::");

            if (parts != null && parts.length > 1)
            {
                if (nonZeroPrimaryTypes.containsKey(parts[0]))
                    defaultColumns.add(col.getFieldKey());
                else
                    col.setHidden(true);
            }
        }
        return defaultColumns;
    }
}
