package org.labkey.api.gwt.client.assay;

/**
 * User: jeckels
 * Date: Apr 13, 2009
 */
public class SampleChooserUtils
{
    public static final String SAMPLE_COUNT_ELEMENT_NAME = "__sampleCount";

    public static final String PROP_NAME_MAX_SAMPLE_COUNT = "maxSampleCount";
    public static final String PROP_NAME_MIN_SAMPLE_COUNT = "minSampleCount";

    public static final String PROP_NAME_DEFAULT_SAMPLE_SET_LSID = "defaultSampleSetLSID";
    public static final String PROP_NAME_DEFAULT_SAMPLE_SET_NAME = "defaultSampleSetName";
    public static final String PROP_NAME_DEFAULT_SAMPLE_SET_ROW_ID = "defaultSampleRowId";
    // Prefix for sample LSIDs that match the barcode
    public static final String PROP_PREFIX_SELECTED_SAMPLE_LSID = "selectedSampleLSID";
    // Prefix for sample set LSIDs for each material that matches the barcode
    public static final String PROP_PREFIX_SELECTED_SAMPLE_SET_LSID = "selectedSampleSetLSID";

    public static final String DUMMY_LSID = "--DUMMY-LSID--";
    
    public static String getLsidFormElementID(int index)
    {
        return "__sample" + index + "LSID";
    }

    public static String getNameFormElementID(int index)
    {
        return "__sample" + index + "Name";
    }
}
