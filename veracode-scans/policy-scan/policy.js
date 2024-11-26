const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { veraocdeConfig, appConfig } = require('../../config');
const { processStaticResultsXML, attacheResult } = require('../../utility/utils');
const { SCAN, STATUS, SCAN_RESPONSE_CODE, PLATFORM_SCAN_STATUS } = require('../../config/constants');
const { getVeracodeApplication, getResourceByAttribute } = require('./common');

async function policyScan(apiId, apiKey, appName, buildId, policyName, teams, createprofile) {
    let artifactFilePath;
    let policyResult = { scan: SCAN.POLICY_SCAN, fileName: appConfig().policyScanResult };
    const resApp = await getVeracodeApplication(apiId, apiKey, appName, policyName, teams, createprofile);
    const veracodeArtifactsDir = path.join(__dirname, '../../veracode-artifacts');
    try {
        const artifacts = await fs.promises.readdir(veracodeArtifactsDir);
        const artifactFile = artifacts[0]; // Assuming there's only one artifact file
        if (!artifactFile) {
            console.log(`${appConfig().logPrefix} No artifact file found in the veracode-artifacts directory.`);
        }
        artifactFilePath = path.join(veracodeArtifactsDir, artifactFile);
    } catch (error) {
        console.log(`${appConfig().logPrefix} Error reading veracode-artifacts directory: ${error}`);
        policyResult.message = `something went wrong while zip : ${error}`;
        policyResult.status = STATUS.Error;
        return policyResult;
    }

    try {
        return triggerPolicyScan(apiId, apiKey, policyResult, resApp, artifactFilePath, buildId);
    }
    catch (error) {
        console.log(`${appConfig().logPrefix} Something went wrong while executing policy scan ${error}`);
        policyResult.message = `something went wrong while executing policy scan ${error}`;
        policyResult.status = STATUS.Error;
    }
    return policyResult;
}

async function triggerPolicyScan(apiId, apiKey, policyResult, resApp, artifactFilePath, buildId) {
    console.log(`Veracode: Policy scan executing...`);
    // let policyScanCommand = `java -jar ${__dirname}/api-wrapper-LATEST/VeracodeJavaAPI.jar -action UploadAndScanByAppId -vid ${apiId} -vkey ${apiKey} -appid ${resApp?.appId} -filepath ${artifactFilePath} -version "${buildId}" -scanpollinginterval 30 - include -autoscan false -scanallnonfataltoplevelmodules false`;
    let debugCommand = `java -jar ${__dirname}/api-wrapper-LATEST/VeracodeJavaAPI.jar -action UploadAndScanByAppId -vid *** -vkey *** -appid ${resApp?.appId} -filepath ${artifactFilePath} -version "${buildId}" -scanpollinginterval 30 - include -autoscan false -scanallnonfataltoplevelmodules false`;
    let scan_id = '';
    try {
        console.log(`Command to execute the policy scan : ${debugCommand}`);
        const args = [
            '-jar', `${__dirname}/api-wrapper-LATEST/VeracodeJavaAPI.jar`,
            '-action', 'UploadAndScanByAppId',
            '-vid', apiId,
            '-vkey', apiKey,
            '-appid', resApp?.appId,
            '-filepath', artifactFilePath,
            '-version', buildId,
            '-scanpollinginterval', '30',
            '-', 'include',
            '-autoscan', 'false',
            '-scanallnonfataltoplevelmodules', 'false'
        ];

        const output = execFileSync('java', args, { encoding: 'utf-8' });

        console.log(`Output from trigger policy scan command :output: ${output}`);
        scan_id = extractValue(output, 'The analysis id of the new analysis is "', '"');
    } catch (error) {
        console.log(`${appConfig().logPrefix} Error while executing veracode policy scan command : ${debugCommand}: ${error}`);
        policyResult.status = STATUS.Error;
        policyResult.message = `Error while executing veracode policy scan command : ${debugCommand}.`;
        return policyResult;
    }
    const scanStatus = await checkPolicyScanStatus(apiId, apiKey, resApp, scan_id);
    console.log(`${appConfig().logPrefix} Policy scan status ${scanStatus}`);

    if (scanStatus === SCAN_RESPONSE_CODE.SCAN_TIME_OUT) {
        policyResult.status = STATUS.Error;
        policyResult.message = `Veracode Policy Scan Exited: Module Selection Timeout Exceeded, Please review the scan on https://analysiscenter.veracode.com/auth/index.jsp#HomeAppProfile:${resApp.oid}:${resApp.appId} Veracode Platform.`;
        return policyResult;
    }
    const veracodeArtifactsDir = path.join(__dirname, '../../veracode-artifacts');
    return getPolicyScanFindings(apiId, apiKey, policyResult, resApp, scan_id, veracodeArtifactsDir);
}

async function getPolicyScanFindings(apiId, apiKey, policyResult, resApp, scan_id, veracodeArtifactsDir) {
    try {
        const debugCommand = `java -jar ${__dirname}/api-wrapper-LATEST/VeracodeJavaAPI.jar -vid *** -vkey *** -action detailedreport -buildid ${scan_id} -outputfilepath "report.xml"`;
        console.log(`Command to get the policy scan result : ${debugCommand}`);
        const args = [
            '-jar', `${__dirname}/api-wrapper-LATEST/VeracodeJavaAPI.jar`,
            '-vid', apiId,
            '-vkey', apiKey,
            '-action', 'detailedreport',
            '-buildid', scan_id,
            '-outputfilepath', 'report.xml'
        ];
        execFileSync('java', args, { stdio: 'inherit' });
        let xml = fs.readFileSync('report.xml', 'utf8');
        const policyscanReport = processStaticResultsXML(xml);
        if (policyscanReport?.policy_results?.findings.length > 0) {
            let issue;
            policyResult.result = JSON.stringify(policyscanReport, null, 2);
            attacheResult(veracodeArtifactsDir, 'policyScan.json', JSON.stringify(policyscanReport, null, 2));
            policyResult.status = STATUS.Findings;
            policyResult.message = 'Vulnerability detected in the repository';
            let findings = policyscanReport.policy_results.findings;
            console.log(`-------------------- Found ${policyscanReport.policy_results.num_findings} Issues ------------------------`);
            for (let finding of findings) {
                issue = `CWE-${finding.static.cwe_id}: ${finding.static.issue_type}: ${finding.static.source_file}:${finding.static.line}`;
                console.log(issue);
            }
        } else {
            policyResult.message = `No policy findings`;
            policyResult.status = STATUS.Success;
        }

    } catch (error) {
        console.log(`${appConfig().logPrefix} error while retriving policy scan result: ${error}`)
        policyResult.status = STATUS.Error;
        policyResult.message = `error while retriving policy scan result: ${error}`;
    }
    return policyResult;
}

async function checkPolicyScanStatus(apiId, apiKey, resApp, scan_id) {
    let endTime = new Date(new Date().getTime() + veraocdeConfig().scanStatusApiTimeout);
    let responseCode = SCAN_RESPONSE_CODE.IN_PROGRESS;
    let moduleSelectionCount = 0;
    let moduleSelectionStartTime = new Date();

    while (true) {
        await sleep(veraocdeConfig().pollingInterval);
        console.log(`${appConfig().logPrefix} veracode: Checking Scan Results for scan_id: ${scan_id}:`);
        const statusUpdate = await getPolicyScanStatus(apiId, apiKey, resApp.appGuid, scan_id);
        console.log(`${appConfig().logPrefix} policy scan status from platform : ${JSON.stringify(statusUpdate)}`)

        if (statusUpdate.status === PLATFORM_SCAN_STATUS.MODULE_SELECTION_REQUIRED || statusUpdate.status === PLATFORM_SCAN_STATUS.PRE_SCAN_SUCCESS) {
            moduleSelectionCount++;
            if (moduleSelectionCount === 1)
                moduleSelectionStartTime = new Date();
            if (new Date().getTime() - moduleSelectionStartTime.getTime() > veraocdeConfig().moduleSelectionTimeout) {
                console.log(`Veracode Policy Scan Exited: Module Selection Timeout Exceeded. Please review the scan on Veracode Platform. https://analysiscenter.veracode.com/auth/index.jsp#HomeAppProfile:${resApp.oid}:${resApp.appId}`);
                return SCAN_RESPONSE_CODE.SCAN_TIME_OUT;
            }
        }

        if ((statusUpdate.status === PLATFORM_SCAN_STATUS.PUBLISHED || statusUpdate.status == PLATFORM_SCAN_STATUS.RESULTS_READY) && statusUpdate.scanUpdateDate) {
            const scanDate = new Date(statusUpdate.scanUpdateDate);
            const policyScanDate = new Date(statusUpdate.lastPolicyScanData);
            if (!policyScanDate || scanDate < policyScanDate) {
                if ((statusUpdate.passFail === 'DID_NOT_PASS' || statusUpdate.passFail == 'CONDITIONAL_PASS')) {
                    console.log(`${appConfig().logPrefix} veracode: Policy Violation: Veracode Policy Scan Failed`);
                    responseCode = SCAN_RESPONSE_CODE.POLICY_EVALUATION_FAILED;
                }
                else {
                    console.log(`${appConfig().logPrefix} Policy Evaluation : ${statusUpdate.passFail}`);
                }
                break;
            } else {
                console.log(`${appConfig().logPrefix} Policy Evaluation: ${statusUpdate.passFail}`);
            }
            return SCAN_RESPONSE_CODE.POLICY_EVALUATION_FAILED;//ToDo: Logic needs to verify
        }

        if (statusUpdate.status != PLATFORM_SCAN_STATUS.SCAN_IN_PROGRESS && endTime < new Date()) {
            console.log(`${appConfig().logPrefix} Veracode Policy Scan Exited: Scan Timeout Exceeded`);
            responseCode = SCAN_RESPONSE_CODE.SCAN_TIME_OUT;
            return responseCode;
        }
    }
    return SCAN_RESPONSE_CODE.FINISHED;
}

async function getPolicyScanStatus(vid, vkey, appGuid, buildId) {
    let resource = {
        resourceUri: `${veraocdeConfig().applicationUri}/${appGuid}`,
        queryAttribute: '',
        queryValue: ''
    };
    const response = await getResourceByAttribute(vid, vkey, resource);
    const scans = response.scans;
    for (let i = 0; i < scans.length; i++) {
        const scanUrl = scans[i].scan_url;
        const scanId = scanUrl.split(':')[3];
        if (scanId === buildId) {
            console.log(`Scan Status of buildId ${buildId} is : ${scans[i].status}`);
            return {
                'status': scans[i].status,
                'passFail': response.profile.policies[0].policy_compliance_status,
                'scanUpdateDate': scans[i].modified_date,
                'lastPolicyScanData': response.last_policy_compliance_check_date
            };
        }
    }
    return {
        'status': 'not found',
        'passFail': 'not found'
    };
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function extractValue(source, prefix, terminator) {
    let start = source.search(prefix);
    let sub1 = source.substring(start + prefix.length);
    let end = sub1.search(terminator);
    return sub1.substring(0, end);
}

module.exports = policyScan;