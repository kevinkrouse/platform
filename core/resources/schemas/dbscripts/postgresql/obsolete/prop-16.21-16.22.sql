/*
 * Copyright (c) 2017-2019 LabKey Corporation
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

-- Re-split the old date-time formats into date-only formats using a slightly better algorithm: truncate at the first
-- space that follows the first "y" or "Y" in the format.

-- Delete the previous date-only formats
DELETE FROM prop.Properties WHERE Set IN (SELECT Set FROM prop.PropertySets WHERE Category = 'LookAndFeel') AND Name = 'defaultDateFormatString';

-- Now insert values for defaultDateFormatString where defaultDateTimeFormatString is defined, using the new approach
INSERT INTO prop.Properties
(
    SELECT Set, 'defaultDateFormatString' AS Name,
        CASE WHEN POSITION('y' IN LOWER(Value)) > 0 THEN  -- Is there a "Y"?
            CASE WHEN POSITION(' ' IN SUBSTRING(Value, POSITION('y' IN LOWER(Value)))) > 0 THEN  -- Is there a space after the "Y"?
                SUBSTRING(Value, 0, POSITION('y' IN LOWER(Value)) + POSITION(' ' IN SUBSTRING(Value, POSITION('y' IN LOWER(Value)))) - 1)
            ELSE
                Value
            END
        ELSE
            Value
        END AS Value
    FROM prop.Properties WHERE Set IN (SELECT Set FROM prop.PropertySets WHERE Category = 'LookAndFeel') AND Name = 'defaultDateTimeFormatString'
);
