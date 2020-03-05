/*
 * Copyright (c) 2019 LabKey Corporation
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

import {List} from "immutable";
import * as React from 'react'
import {ActionURL} from "@labkey/api";
import {
    IBannerMessage,
    SampleTypeDesigner,
    getHelpLink,
    LoadingPage,
    getSampleTypeDetails,
    SchemaQuery,
    DomainDetails,
    SAMPLE_TYPE,
    IDomainField,
    getSampleSet,
    initQueryGridState,
    Alert
} from "@labkey/components"

import "@labkey/components/dist/components.css"
import "./sampleTypeDesigner.scss";

interface IAppState {
    dirty: boolean
    sampleType: DomainDetails
    rowId: number
    domainId?: number
    messages?: List<IBannerMessage>,
    queryName: string
    returnUrl: string
    schemaName: string
    showConfirm: boolean
    submitting: boolean
    includeWarnings: boolean
    showWarnings: boolean
    badDomain: DomainDetails
}

const CREATE_SAMPLE_SET_ACTION = 'createSampleSet';

//TODO should these be moved to a constants file? or shared through components?
export const NAME_EXPRESSION_TOPIC = 'sampleIDs#expression';
export const DEFAULT_SAMPLE_FIELD_CONFIG = {
    required: true,
    dataType: SAMPLE_TYPE,
    conceptURI: SAMPLE_TYPE.conceptURI,
    rangeURI: SAMPLE_TYPE.rangeURI,
    lookupSchema: 'exp',
    lookupQuery: 'Materials',
    lookupType: {...SAMPLE_TYPE},
    name: 'SampleId',
} as Partial<IDomainField>;

export class App extends React.PureComponent<any, Partial<IAppState>> {

    constructor(props) {
        super(props);

        initQueryGridState();
        const { RowId, schemaName, queryName, domainId, returnUrl } = ActionURL.getParameters();
        const action = ActionURL.getAction();

        let messages = (action !== CREATE_SAMPLE_SET_ACTION) ?
            this.checkUpdateActionParameters(schemaName, queryName, domainId, RowId,) :
            List<IBannerMessage>();

        this.state = {
            schemaName,
            queryName,
            domainId,
            rowId: RowId,
            returnUrl,
            submitting: false,
            messages,
            showConfirm: false,
            dirty: false,
            includeWarnings: true
        };
    }

    componentDidMount() {
        const { domainId, schemaName, queryName, rowId, messages } = this.state;

        //These will allow direct querying of the domain design
        if ((schemaName && queryName) || domainId ) {
            this.fetchSampleTypeDomain(domainId, schemaName, queryName);
        }
        else if (rowId) {
            //Get SampleType from experiment service
            getSampleSet({rowId})
                .then(results => {
                    const sampleSet = results.get('sampleSet');
                    const {domainId} = sampleSet;

                    // Then query for actual domain design
                    this.fetchSampleTypeDomain(domainId);
                })
                .catch(error => {
                    this.setState(() => ({
                        messages: messages.set(0, {message: error.exception, messageType: 'danger'})
                    }));
                });
        }
        else {
            //Creating a new Sample Type
            this.setState(()=>({
                sampleType: DomainDetails.create()
            }));
        }

        window.addEventListener("beforeunload", this.handleWindowBeforeUnload);
    }

    /**
     * Verify that the needed parameters are supplied either
     * @param schemaName of sample type
     * @param queryName of sample type
     * @param rowId of sample type
     * @returns List of error messages
     */
    private checkUpdateActionParameters = (schemaName: string, queryName: string, domainId: number, rowId: number): List<IBannerMessage> => {
        let messages = List<IBannerMessage>();

        if ( (!schemaName || !queryName) && !domainId && !rowId) {
            let msg =  'Need at least one required identifier: rowId, domainId, or schemaName and queryName.';
            let msgType = 'danger';
            let bannerMsg ={message: msg, messageType: msgType};
            messages = messages.push(bannerMsg);
        }

        return messages;
    };

    /**
     * Look up full Sample Type domain, including fields
     **/
    private fetchSampleTypeDomain = (domainId, schemaName?, queryName?): void => {
        getSampleTypeDetails( SchemaQuery.create(schemaName, queryName), domainId)
            .then( results => {
                const sampleType = results;
                this.setState(()=> ({sampleType}));
            }).catch(error => {
                const {messages} = this.state;

                this.setState(() => ({
                    messages: messages.set(0, {message: error.exception, messageType: 'danger'})
                }));
            }
        );
    };

    handleWindowBeforeUnload = (event) => {
        if (this.state.dirty) {
            event.returnValue = 'Changes you made may not be saved.';
        }
    };

    componentWillUnmount() {
        window.removeEventListener("beforeunload", this.handleWindowBeforeUnload);
    }

    submitAndNavigate = (response: any) => {
        this.setState(() => ({
            submitting: false,
            dirty: false
        }));

        this.showMessage("Save Successful", 'success', 0);

        this.navigate();
    };

    dismissAlert = (index: any) => {
        this.setState(() => ({
            messages: this.state.messages.setIn([index], [{message: undefined, messageType: undefined}])
        }));
    };

    showMessage = (message: string, messageType: string, index: number, additionalState?: Partial<IAppState>) => {
        const { messages } = this.state;

        this.setState(Object.assign({}, additionalState, {
            messages : messages.set(index, {message: message, messageType: messageType})
        }));
    };

    onCancelBtnHandler = () => {
        this.navigate();
    };

    navigate = () => {
        const { returnUrl } = this.state;
        this.setState(() => ({dirty: false}), () => {
            window.location.href = returnUrl || ActionURL.buildURL('project', 'begin', LABKEY.container.path);
        });
    };

    beforeFinish = ():void => {}; //TODO may need something here...

    render() {
        const {menuLoading} = this.props;
        const {sampleType, messages} = this.state;
        const subtitle = 'Edit Sample Type Details';

        if (menuLoading) {
            return <LoadingPage title={subtitle}/>
        }

        return (
            <>
                { messages && messages.size > 0 && messages.map((bannerMessage, idx) => {
                    return (<Alert key={idx} bsStyle={bannerMessage.messageType} onDismiss={() => this.dismissAlert(idx)}>{bannerMessage.message}</Alert>) })
                }

                {sampleType &&
                <SampleTypeDesigner
                        initModel={sampleType}
                        nameExpressionInfoUrl={getHelpLink(NAME_EXPRESSION_TOPIC)}
                        beforeFinish={this.beforeFinish}
                        onComplete={this.submitAndNavigate}
                        onCancel={this.onCancelBtnHandler}
                        defaultSampleFieldConfig={DEFAULT_SAMPLE_FIELD_CONFIG}
                        includeDataClasses={true}
                        useTheme={true}
                        appPropertiesOnly={false}
                />
                }
            </>
        )
    }
}

