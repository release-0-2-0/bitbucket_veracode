const { execSync } = require('child_process');
const path = require('path');
const { attacheResult } = require('../../utility/utils');

async function scaScan(clone_url, scaAgenToken, scaUrl) {
  try {
    const command = `curl -sSL https://download.sourceclear.com/ci.sh | sh -s -- scan --url ${clone_url} --recursive --allow-dirty`;
    const output = execSync(command, { encoding: 'utf-8', env: { ...process.env, SRCCLR_API_TOKEN: scaAgenToken, SRCCLR_API_URL: scaUrl } });
    console.log(`Veracode SCA scan executed successfully.`);
    console.log(output);

    const jsonCommand = `curl -sSL https://download.sourceclear.com/ci.sh | sh -s -- scan --url ${clone_url} --json=scaScan.json --recursive --allow-dirty`;
    const jsonOutput = execSync(jsonCommand, { encoding: 'utf-8', env: { ...process.env, SRCCLR_API_TOKEN: scaAgenToken, SRCCLR_API_URL: scaUrl } });
    if (output.includes("Full Report Details")) {
      const veracodeArtifactsDir = path.join(__dirname, '../../veracode-artifacts');
      attacheResult(veracodeArtifactsDir, 'scaScan.json', jsonOutput);
    }

  } catch (error) {
    console.error(`Error occurred during SCA scan: ${error.message}`);
  }
}

module.exports = scaScan;