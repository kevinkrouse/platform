/*
 * Copyright (c) 2012 LabKey Corporation
 *
 * Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
 */

if(!LABKEY){
	var LABKEY = {};
}

if(!LABKEY.vis){
	LABKEY.vis = {};
}

/********** Stats **********/

if(!LABKEY.vis.Stat){
	LABKEY.vis.Stat = {};
}

LABKEY.vis.Stat.summary = function(data, accessor){
    /*
        Returns an object with the min, max, Q1, Q2 (median), Q3, interquartile range, and the sorted array of values.
     */
    var summary = {};

    summary.sortedValues = LABKEY.vis.Stat.sortNumericAscending(data, accessor);
    summary.min = summary.sortedValues[0];
    summary.max = summary.sortedValues[summary.sortedValues.length -1];
    summary.Q1 = LABKEY.vis.Stat.Q1(summary.sortedValues);
    summary.Q2 = LABKEY.vis.Stat.Q2(summary.sortedValues);
    summary.Q3 = LABKEY.vis.Stat.Q3(summary.sortedValues);
    summary.IQR = summary.Q3 - summary.Q1;

    return summary;
};

LABKEY.vis.Stat.Q1 = function(numbers){
    return d3.quantile(numbers,0.25);
};

LABKEY.vis.Stat.Q2 = LABKEY.vis.Stat.median = function(numbers){
    return d3.quantile(numbers,0.5);
};

LABKEY.vis.Stat.Q3 = function(numbers){
    return d3.quantile(numbers,0.75);
};

LABKEY.vis.Stat.sortNumericAscending = function(data, accessor){
    var numbers = [];
    for(var i = 0; i < data.length; i++){
        numbers.push(accessor(data[i]));
    }
    numbers.sort(function(a, b){return a-b;});
    return numbers;
};

LABKEY.vis.Stat.sortNumericDescending = function(data, accessor){
    var numbers = [];
    for(var i = 0; i < data.length; i++){
        numbers.push(accessor(data[i]));
    }
    numbers.sort(function(a, b){return b-a;});
    return numbers;
};
