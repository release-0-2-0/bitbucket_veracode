const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { SCAN, STATUS } = require('../../config/constants');
const { appConfig } = require('../../config');
const { attacheResult } = require('../../utility/utils');

async function pipelineScan(apiId, apiKey) {
  const pipelineScanFile = appConfig().pipelineScanFile;
  const filteredScanFile = appConfig().filteredScanFile;
  let pipelineResult = { scan: SCAN.PIPELINE_SCAN, fileName: pipelineScanFile };
  let artifactFilePath;
  const pipelineScanJarPath = path.join(__dirname, 'pipeline-scan.jar');
  const veracodeArtifactsDir = '/opt/atlassian/pipelines/agent/build/veracode-artifacts';//path.join(__dirname, '../../veracode-artifacts'); 
  try {
    const artifacts = await fs.promises.readdir(veracodeArtifactsDir);
    console.log("artifacts: ", artifacts);
    const artifactFile = artifacts[0]; // Assuming there's only one artifact file
        console.log("artifactFile: ", artifactFile);
    if (!artifactFile) {
      console.log('No artifact file found in the veracode-artifacts directory.');
    }
    artifactFilePath = path.join(veracodeArtifactsDir, artifactFile);
    const debugCommand = `java -jar ${pipelineScanJarPath} -vid *** -vkey *** -f ${artifactFilePath} -jf ${pipelineScanFile} -fjf ${filteredScanFile}`;
    console.log(`Pipeline command: ${debugCommand}`);
    const args = [
      '-jar', pipelineScanJarPath,
      '-vid', apiId,
      '-vkey', apiKey,
      '-f', artifactFilePath,
      '-jf', pipelineScanFile,
      '-fjf', filteredScanFile
    ];
    
    try {
      execFileSync('java', args, { encoding: 'utf-8' });
    } catch (error) {
      console.log(`Pipeline scan result ${error?.stdout?.toString()}`);
      var rawdata = fs.readFileSync(pipelineScanFile);
      var results = JSON.parse(rawdata.toString());
      attacheResult(veracodeArtifactsDir, 'pipelineScan.json', JSON.stringify(results, null, 2));
      pipelineResult.result = JSON.stringify(results, null, 2);
      pipelineResult.status = STATUS.Findings;
      pipelineResult.message = 'Vulnerability detected in the repository';
      return pipelineResult;
    }
    console.log("No pipeline findings.");
    pipelineResult.message = `No pipeline findings.`;
    pipelineResult.status = STATUS.Success;
    return pipelineResult;
  } catch (error) {
  console.log(error);
    console.error(`Error: ${error}`);
  }
}

module.exports = pipelineScan;