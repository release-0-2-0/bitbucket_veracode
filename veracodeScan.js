const pipelineScan = require('./veracode-scans/pipeline-scan/pipeline');
const policyScan = require('./veracode-scans/policy-scan/policy');
const removeSandboxScan = require('./veracode-scans/policy-scan/remove-sandbox');
const sandboxScan = require('./veracode-scans/policy-scan/sandbox');
const scaScan = require('./veracode-scans/sca-scan/sca-scan');

async function veracodeScan() {
    const projectName = process.env.PROJECT_NAME;
    const executePipeline = process.env.EXECUTE_PIPELINE;
    const executePolicy = process.env.EXECUTE_POLICY;
    const executeSandbox = process.env.EXECUTE_SANDBOX;
    const executeRemoveSandbox = process.env.EXECUTE_REMOVE_SANDBOX;
    const executeSca = process.env.EXECUTE_SCA;
    const executeIac = process.env.EXECUTE_IAC;
    const breakBuildOnFinding = process.env.BREAK_BUILD_ON_FINDING;
    const breakBuildOnError = process.env.BREAK_BUILD_ON_ERROR;
    const commitSha = process.env.COMMIT_SHA;
    const sourceProjectId = process.env.PROJECT_ID;
    const policyName = process.env.POLICY_NAME || '';
    const createProfile = true;
    const sourceRepoCloneUrl = process.env.CLONE_URL;
    const scaAgenToken = process.env.VERACODE_AGENT_TOKEN;
    const scaUrl = process.env.VERACODE_SRCCLR_URL;
    const sourceBranch = process.env.SOURCE_BRANCH;
    const appProfileName = process.env.PROFILE_NAME;

    const ciPipelineId = process.env.CI_PIPELINE_ID;

    const apiId = process.env.VERACODE_API_ID;
    const appKey = process.env.VERACODE_API_KEY;
console.log("apiId: ", apiId);
    if (executePipeline) {
        console.log(`Executing pipeline scan on ${projectName} repo for ${commitSha} commit`);
        await pipelineScan(apiId, appKey);
    }
    if (executeSandbox) {
        console.log(`Executing sandbox scan on ${projectName} repo for ${commitSha} commit`);
        sandboxScan(apiId, appKey, sourceBranch, policyName, '', createProfile, ciPipelineId, appProfileName)
    }
    if (executePolicy) {
        console.log(`Executing policy scan on ${projectName} repo for ${commitSha} commit`);
        await policyScan(apiId, appKey, appProfileName, ciPipelineId, policyName, '', createProfile);
    }
    if (executeRemoveSandbox) {
        console.log(`Executing removed sandbox scan on ${projectName} repo for ${commitSha} commit`);
        removeSandboxScan(apiId, appKey, sourceBranch, appProfileName)
    }
    if (executeSca) {
        console.log(`Executing sca scan on ${projectName} repo for ${commitSha} commit`);
        await scaScan(sourceRepoCloneUrl, scaAgenToken, scaUrl);
    }
    if (executeIac) {
        console.log(`Executing iac scan on ${projectName} repo for ${commitSha} commit`);
    }
}
veracodeScan();