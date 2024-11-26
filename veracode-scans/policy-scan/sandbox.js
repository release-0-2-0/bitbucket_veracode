const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { veraocdeConfig } = require('../../config');
const { getVeracodeApplication } = require('./common');

async function sandboxScan(apiId, apiKey, sourceBranch, policyName, teams, createprofile, buildId, appName) {
    let resApp;
    try {
        resApp = await getVeracodeApplication(apiId, apiKey, appName, policyName, teams, createprofile);
    } catch (error) {
        console.log(`Error while retriving application details for ${appName}`, error);
        return;
    }

    let artifactFilePath;
    try {
        const veracodeArtifactsDir = path.join(__dirname, '../../veracode-artifacts');
        const artifacts = await fs.promises.readdir(veracodeArtifactsDir);
        const artifactFile = artifacts[0]; // Assuming there's only one artifact file
        if (!artifactFile) {
            console.log(`No artifact file found in the veracode-artifacts directory.`);
        }
        artifactFilePath = path.join(veracodeArtifactsDir, artifactFile);
    } catch (error) {
        console.log(`Error reading veracode-artifacts directory: ${error}`);
        return;
    }

    try {
        triggerSandboxScan(apiId, apiKey, resApp, artifactFilePath, sourceBranch, buildId);
    } catch (error) {
        console.log(`Error while executing sandbox scan on ${sourceBranch} branch: `, error);
        return;
    }
}

async function triggerSandboxScan(apiId, apiKey, resApp, artifactFilePath, sourceBranch, buildId) {
    const sandboxName = `${veraocdeConfig().sandboxScanName}${sourceBranch}`;
    const args = [
        '-jar', `${__dirname}/api-wrapper-LATEST/VeracodeJavaAPI.jar`,
        '-action', 'UploadAndScanByAppId',
        '-vid', apiId,
        '-vkey', apiKey,
        '-appid', resApp?.appId,
        '-filepath', artifactFilePath,
        '-version', buildId,
        '-sandboxname', sandboxName,
        '-createsandbox', 'true',
        '-scanpollinginterval', '30',
        '-', 'include',
        '-autoscan', 'false',
        '-scanallnonfataltoplevelmodules', 'false'
    ];

    try {
        const output = execFileSync('java', args, { encoding: 'utf-8' });
        console.log(`Output from sandbox scan command: ${output}`);
    } catch (error) {
        console.log("Sandbox error : ");
        console.log(error);
    }    
}


module.exports = sandboxScan;